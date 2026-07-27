"""Evaluator-signed production registration for held-out QA evaluation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .scoring import EvaluationContractError

_REGISTRATION_FIELDS = {
    "schema_version",
    "suite_id",
    "authority",
    "key_id",
    "algorithm",
    "issued_at",
    "corpus_frozen_at",
    "baseline_frozen_at",
    "candidate_frozen_at",
    "gold_revealed_at",
    "evaluation_completed_at",
    "manifest_sha256",
    "observations_sha256",
    "baseline_sha256",
    "thresholds_sha256",
    "corpus_sha256",
    "budget_contract_sha256",
    "evaluator_bundle_sha256",
    "slo_input_set_sha256",
    "slo_thresholds_sha256",
    "slo_sampling_contract_sha256",
    "candidate",
    "baseline",
}
_IDENTITY_FIELDS = {
    "agent_bundle_sha256",
    "policy_sha256",
    "tool_registry_sha256",
}
_SIGNATURE_DOMAIN = (
    b"automated-qa-test/production-evaluation-registration/v2\n"
)
_REGISTRATION_SCHEMA_VERSION = 2
_TRUST_SCHEMA_VERSION = 2
_MAX_REGISTRATION_AGE = timedelta(days=30)
_MAX_TRUST_SNAPSHOT_AGE = timedelta(hours=24)
_MAX_TRUST_SNAPSHOT_HORIZON = timedelta(hours=24)
_MAX_EVALUATOR_BUNDLE_FILES = 4_096
_MAX_EVALUATOR_BUNDLE_BYTES = 128 * 1024 * 1024
_MAX_EVALUATOR_BUNDLE_DEPTH = 32
_MAX_EVALUATOR_BUNDLE_FILE_BYTES = 32 * 1024 * 1024
_MAX_CANDIDATE_REGISTRATION_BYTES = 64 * 1024
_MAX_CANDIDATE_SOURCE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerifiedProductionRegistration:
    """A signature-verified evaluator statement bound to all scored inputs."""

    suite_id: str
    authority: str
    key_id: str
    issued_at: str
    registration_sha256: str
    signed_payload_sha256: str
    evaluator_bundle_sha256: str
    slo_input_set_sha256: str
    slo_thresholds_sha256: str
    slo_sampling_contract_sha256: str
    candidate_identity: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "authority": self.authority,
            "key_id": self.key_id,
            "algorithm": "Ed25519",
            "issued_at": self.issued_at,
            "registration_sha256": self.registration_sha256,
            "signed_payload_sha256": self.signed_payload_sha256,
            "evaluator_bundle_sha256": self.evaluator_bundle_sha256,
            "slo_input_set_sha256": self.slo_input_set_sha256,
            "slo_thresholds_sha256": self.slo_thresholds_sha256,
            "slo_sampling_contract_sha256": (
                self.slo_sampling_contract_sha256
            ),
            "candidate_identity": dict(self.candidate_identity),
        }


def verify_production_registration(
    *,
    manifest: Mapping[str, Any],
    observations: Mapping[str, Any],
    baseline: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    registration: Mapping[str, Any] | None,
    trust_config: Mapping[str, Any] | None,
    suite_id: str,
    evaluator_bundle_root: str | os.PathLike[str] | None,
    now: datetime | None = None,
) -> VerifiedProductionRegistration:
    """Verify the detached Ed25519 registration and every content binding."""

    if registration is None:
        raise EvaluationContractError(
            "production_registration_missing",
            "production scoring requires an evaluator-signed registration",
        )
    if trust_config is None:
        raise EvaluationContractError(
            "production_trust_missing",
            "production scoring requires a trusted evaluator key allowlist",
        )
    payload = _strict_object(
        "registration",
        registration,
        required={*_REGISTRATION_FIELDS, "signature"},
    )
    if payload["schema_version"] != _REGISTRATION_SCHEMA_VERSION:
        raise EvaluationContractError(
            "production_registration_schema_unsupported",
            (
                "registration.schema_version must equal "
                f"{_REGISTRATION_SCHEMA_VERSION}"
            ),
        )
    if _text("registration.suite_id", payload["suite_id"]) != suite_id:
        raise EvaluationContractError(
            "production_registration_suite_mismatch",
            "registration.suite_id must match manifest.suite_id",
        )
    authority = _text("registration.authority", payload["authority"])
    key_id = _text("registration.key_id", payload["key_id"])
    if payload["algorithm"] != "Ed25519":
        raise EvaluationContractError(
            "production_registration_algorithm_invalid",
            "registration.algorithm must equal Ed25519",
        )

    times = {
        name: _timestamp(f"registration.{name}", payload[name])
        for name in (
            "corpus_frozen_at",
            "baseline_frozen_at",
            "candidate_frozen_at",
            "gold_revealed_at",
            "evaluation_completed_at",
            "issued_at",
        )
    }
    ordered_names = (
        "corpus_frozen_at",
        "baseline_frozen_at",
        "candidate_frozen_at",
        "gold_revealed_at",
        "evaluation_completed_at",
        "issued_at",
    )
    if any(
        times[right] <= times[left]
        for left, right in zip(ordered_names, ordered_names[1:])
    ):
        raise EvaluationContractError(
            "production_registration_time_order_invalid",
            (
                "registration timestamps must satisfy corpus_frozen_at < "
                "baseline_frozen_at < candidate_frozen_at < "
                "gold_revealed_at < evaluation_completed_at < issued_at"
            ),
        )

    trusted_now = _trusted_now(now)
    if times["issued_at"] > trusted_now:
        raise EvaluationContractError(
            "production_registration_issued_in_future",
            "registration.issued_at must not be later than trusted now",
        )
    if trusted_now - times["issued_at"] > _MAX_REGISTRATION_AGE:
        raise EvaluationContractError(
            "production_registration_stale",
            "registration exceeds the maximum production age of 30 days",
        )

    expected_hashes = {
        "manifest_sha256": _canonical_sha256(manifest),
        "observations_sha256": _canonical_sha256(observations),
        "baseline_sha256": _canonical_sha256(baseline),
        "thresholds_sha256": _canonical_sha256(thresholds),
        "corpus_sha256": _canonical_sha256(manifest.get("cases")),
        "budget_contract_sha256": _budget_contract_sha256(manifest),
    }
    for field, expected in expected_hashes.items():
        observed = _sha256(f"registration.{field}", payload[field])
        if observed != expected:
            raise EvaluationContractError(
                "production_registration_binding_mismatch",
                f"registration.{field} does not bind the scored input",
            )

    evaluator_bundle_sha256 = _sha256(
        "registration.evaluator_bundle_sha256",
        payload["evaluator_bundle_sha256"],
    )
    slo_input_set_sha256 = _sha256(
        "registration.slo_input_set_sha256",
        payload["slo_input_set_sha256"],
    )
    slo_thresholds_sha256 = _sha256(
        "registration.slo_thresholds_sha256",
        payload["slo_thresholds_sha256"],
    )
    slo_sampling_contract_sha256 = _sha256(
        "registration.slo_sampling_contract_sha256",
        payload["slo_sampling_contract_sha256"],
    )
    if evaluator_bundle_root is None:
        raise EvaluationContractError(
            "production_evaluator_bundle_unavailable",
            (
                "production scoring requires the evaluator-owned bundle "
                "directory so its digest can be recomputed from regular files"
            ),
        )
    observed_evaluator_bundle_sha256 = hash_evaluator_bundle(
        evaluator_bundle_root
    )
    if observed_evaluator_bundle_sha256 != evaluator_bundle_sha256:
        raise EvaluationContractError(
            "production_evaluator_bundle_content_mismatch",
            (
                "registration.evaluator_bundle_sha256 does not match the "
                "bounded evaluator bundle tree"
            ),
        )
    independence = manifest.get("independence")
    if not isinstance(independence, Mapping):
        raise EvaluationContractError(
            "production_independence_unconfirmed",
            "manifest.independence must be an object",
        )
    if independence.get("evaluator_owner") != authority:
        raise EvaluationContractError(
            "production_evaluator_owner_mismatch",
            "signed registration authority must match evaluator_owner",
        )
    if independence.get("evaluator_bundle_hash") != evaluator_bundle_sha256:
        raise EvaluationContractError(
            "production_evaluator_bundle_mismatch",
            "signed evaluator bundle hash must match manifest independence",
        )
    if manifest.get("frozen_at") != payload["corpus_frozen_at"]:
        raise EvaluationContractError(
            "production_manifest_freeze_mismatch",
            "manifest.frozen_at must match signed corpus_frozen_at",
        )
    if baseline.get("frozen_at") != payload["baseline_frozen_at"]:
        raise EvaluationContractError(
            "production_baseline_freeze_mismatch",
            "baseline.frozen_at must match signed baseline_frozen_at",
        )
    if baseline.get("corpus_hash") != expected_hashes["corpus_sha256"]:
        raise EvaluationContractError(
            "production_baseline_corpus_mismatch",
            "baseline.corpus_hash must bind the held-out cases",
        )
    if (
        baseline.get("budget_contract_hash")
        != expected_hashes["budget_contract_sha256"]
    ):
        raise EvaluationContractError(
            "production_baseline_budget_mismatch",
            "baseline.budget_contract_hash must bind the candidate budgets",
        )

    candidate = _strict_object(
        "registration.candidate",
        payload["candidate"],
        required={*_IDENTITY_FIELDS, "model_id", "memory_snapshot_sha256"},
    )
    baseline_identity = _strict_object(
        "registration.baseline",
        payload["baseline"],
        required=_IDENTITY_FIELDS,
    )
    _verify_candidate_identity(observations, candidate)
    _verify_baseline_identity(baseline, baseline_identity)
    if (
        candidate["agent_bundle_sha256"]
        == baseline_identity["agent_bundle_sha256"]
    ):
        raise EvaluationContractError(
            "production_baseline_candidate_not_distinct",
            "deterministic baseline and candidate agent bundle must differ",
        )

    public_key = _trusted_public_key(
        trust_config,
        authority=authority,
        key_id=key_id,
        suite_id=suite_id,
        registration_issued_at=times["issued_at"],
        now=trusted_now,
    )
    signature = _signature(payload["signature"])
    unsigned = {field: payload[field] for field in sorted(_REGISTRATION_FIELDS)}
    signed_bytes = _SIGNATURE_DOMAIN + _canonical_bytes(unsigned)
    try:
        public_key.verify(signature, signed_bytes)
    except InvalidSignature as exc:
        raise EvaluationContractError(
            "production_registration_signature_invalid",
            "evaluator registration Ed25519 signature is invalid",
        ) from exc
    return VerifiedProductionRegistration(
        suite_id=suite_id,
        authority=authority,
        key_id=key_id,
        issued_at=payload["issued_at"],
        registration_sha256=_canonical_sha256(payload),
        signed_payload_sha256=hashlib.sha256(signed_bytes).hexdigest(),
        evaluator_bundle_sha256=evaluator_bundle_sha256,
        slo_input_set_sha256=slo_input_set_sha256,
        slo_thresholds_sha256=slo_thresholds_sha256,
        slo_sampling_contract_sha256=slo_sampling_contract_sha256,
        candidate_identity={
            "agent_bundle_sha256": candidate["agent_bundle_sha256"],
            "policy_sha256": candidate["policy_sha256"],
            "tool_registry_sha256": candidate["tool_registry_sha256"],
            "model_id": candidate["model_id"],
            "memory_snapshot_sha256": candidate[
                "memory_snapshot_sha256"
            ],
        },
    )


def production_registration_signing_payload(
    registration: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact unsigned payload an external evaluator must sign."""

    payload = _strict_object(
        "registration",
        registration,
        required=_REGISTRATION_FIELDS,
        optional={"signature"},
    )
    return {field: payload[field] for field in sorted(_REGISTRATION_FIELDS)}


def production_registration_signing_bytes(
    registration: Mapping[str, Any],
) -> bytes:
    """Return domain-separated canonical bytes for detached signing."""

    return _SIGNATURE_DOMAIN + _canonical_bytes(
        production_registration_signing_payload(registration)
    )


def verify_candidate_identity_sources(
    *,
    registration_path: str | os.PathLike[str],
    agent_bundle_root: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    memory_snapshot_path: str | os.PathLike[str],
    model_id: str,
    execution_source_paths: Mapping[str, str | os.PathLike[str]],
) -> dict[str, Any]:
    """Recompute a run candidate identity from concrete bounded sources.

    This is a pre-dispatch identity compiler, not an authorization decision.
    The returned snapshot is safe to commit into a run attempt and later
    re-verify without retaining mutable external paths.
    """

    from qa_core.tools import build_default_tool_registry

    from .io import read_json_object, require_distinct_inputs

    registration_snapshot = read_json_object(
        registration_path,
        label="candidate_identity_registration",
        maximum_bytes=_MAX_CANDIDATE_REGISTRATION_BYTES,
    )
    policy_snapshot = read_json_object(
        policy_path,
        label="candidate_policy",
        maximum_bytes=_MAX_CANDIDATE_SOURCE_BYTES,
    )
    memory_snapshot = read_json_object(
        memory_snapshot_path,
        label="candidate_memory_snapshot",
        maximum_bytes=_MAX_CANDIDATE_SOURCE_BYTES,
    )
    require_distinct_inputs(
        (registration_snapshot, policy_snapshot, memory_snapshot)
    )
    payload = _strict_object(
        "candidate_identity_registration",
        registration_snapshot.value,
        required={
            "schema_version",
            *_IDENTITY_FIELDS,
            "model_id",
            "memory_snapshot_sha256",
        },
    )
    if payload["schema_version"] != 1:
        raise EvaluationContractError(
            "candidate_identity_registration_schema_unsupported",
            "candidate identity registration schema_version must equal 1",
        )
    normalized_model_id = _text("candidate.model_id", model_id)
    bundle_manifest = _snapshot_evaluator_bundle(agent_bundle_root)
    execution_sources = _bind_candidate_execution_sources(
        agent_bundle_root,
        execution_source_paths,
        bundle_manifest=bundle_manifest,
    )
    final_bundle_manifest = _snapshot_evaluator_bundle(agent_bundle_root)
    if final_bundle_manifest != bundle_manifest:
        raise EvaluationContractError(
            "candidate_identity_execution_bundle_changed",
            (
                "agent bundle changed while execution sources were "
                "bound to the candidate identity"
            ),
        )
    actual = {
        "agent_bundle_sha256": _canonical_sha256(bundle_manifest),
        "policy_sha256": policy_snapshot.sha256,
        "tool_registry_sha256": (
            build_default_tool_registry().canonical_sha256
        ),
        "model_id": normalized_model_id,
        "memory_snapshot_sha256": memory_snapshot.sha256,
    }
    for field, observed in actual.items():
        declared = (
            _text(f"candidate.{field}", payload[field])
            if field == "model_id"
            else _sha256(f"candidate.{field}", payload[field])
        )
        if declared != observed:
            raise EvaluationContractError(
                "candidate_identity_source_mismatch",
                f"candidate identity field does not match its source: {field}",
            )
    identity_sha256 = _canonical_sha256(actual)
    normalized_registration = {
        "schema_version": 1,
        **actual,
    }
    return {
        "schema_version": 2,
        "candidate_identity": actual,
        "candidate_identity_sha256": identity_sha256,
        "registration": normalized_registration,
        "registration_sha256": _canonical_sha256(
            normalized_registration
        ),
        "source_bindings": {
            "agent_bundle_tree_sha256": actual[
                "agent_bundle_sha256"
            ],
            "policy_file_sha256": actual["policy_sha256"],
            "tool_registry_sha256": actual["tool_registry_sha256"],
            "model_id": actual["model_id"],
            "memory_snapshot_file_sha256": actual[
                "memory_snapshot_sha256"
            ],
            "execution_sources": execution_sources,
            "execution_sources_sha256": _canonical_sha256(
                execution_sources
            ),
        },
        "not_authorization": True,
    }


def hash_evaluator_bundle(
    root: str | os.PathLike[str],
) -> str:
    """Hash a bounded, symlink-free tree of single-linked regular files.

    The digest covers each relative POSIX path, byte size, file mode and
    content digest.  Directory entries are traversed through ``dir_fd`` handles
    with ``O_NOFOLLOW`` so a path swap cannot redirect a production verifier
    outside the evaluator-owned root.
    """

    return _canonical_sha256(_snapshot_evaluator_bundle(root))


def _snapshot_evaluator_bundle(
    root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Return one bounded, symlink-free bundle manifest."""

    candidate = Path(root).expanduser()
    if candidate.is_symlink():
        raise EvaluationContractError(
            "production_evaluator_bundle_symlink_rejected",
            "evaluator bundle root must not be a symlink",
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise EvaluationContractError(
            "production_evaluator_bundle_unavailable",
            f"cannot open evaluator bundle root: {candidate}",
        ) from exc
    entries: list[dict[str, Any]] = []
    seen_files: set[tuple[int, int]] = set()
    total_bytes = 0
    try:
        root_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise EvaluationContractError(
                "production_evaluator_bundle_not_directory",
                "evaluator bundle root must be a directory",
            )
        total_bytes = _walk_evaluator_bundle(
            descriptor,
            relative_parts=(),
            depth=0,
            entries=entries,
            seen_files=seen_files,
            total_bytes=total_bytes,
        )
    finally:
        os.close(descriptor)
    if not entries:
        raise EvaluationContractError(
            "production_evaluator_bundle_empty",
            "evaluator bundle must contain at least one regular file",
        )
    manifest = {
        "schema_version": 1,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": sorted(entries, key=lambda item: str(item["path"])),
    }
    return manifest


def _bind_candidate_execution_sources(
    root: str | os.PathLike[str],
    source_paths: Mapping[str, str | os.PathLike[str]],
    *,
    bundle_manifest: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Bind actual runtime source paths to entries in the hashed bundle.

    This proves a filesystem source snapshot only. It intentionally makes no
    claim about already-loaded process memory or remote model weights.
    """

    if not isinstance(source_paths, Mapping) or not source_paths:
        raise EvaluationContractError(
            "candidate_identity_execution_sources_invalid",
            "candidate execution sources must be a non-empty mapping",
        )
    try:
        root_path = Path(root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise EvaluationContractError(
            "candidate_identity_execution_bundle_mismatch",
            "candidate bundle root cannot be resolved",
        ) from exc
    files = bundle_manifest.get("files")
    if not isinstance(files, list):
        raise EvaluationContractError(
            "candidate_identity_execution_sources_invalid",
            "candidate bundle manifest is missing its file list",
        )
    manifest_by_path = {
        str(item.get("path")): item
        for item in files
        if isinstance(item, Mapping)
        and isinstance(item.get("path"), str)
    }
    bindings: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for component, source_path in sorted(
        source_paths.items(),
        key=lambda item: str(item[0]),
    ):
        normalized_component = _text(
            "candidate.execution_source.component",
            component,
        )
        if (
            len(normalized_component) > 256
            or "/" in normalized_component
            or "\\" in normalized_component
            or "\x00" in normalized_component
        ):
            raise EvaluationContractError(
                "candidate_identity_execution_sources_invalid",
                "candidate execution source component is not canonical",
            )
        try:
            resolved_source = (
                Path(source_path).expanduser().resolve(strict=True)
            )
            relative_path = resolved_source.relative_to(
                root_path
            ).as_posix()
        except (OSError, ValueError, TypeError) as exc:
            raise EvaluationContractError(
                "candidate_identity_execution_bundle_mismatch",
                (
                    "actual execution source is outside the hashed "
                    f"candidate bundle: {normalized_component}"
                ),
            ) from exc
        expected_paths = _candidate_execution_component_paths(
            normalized_component
        )
        if relative_path not in expected_paths:
            raise EvaluationContractError(
                "candidate_identity_execution_bundle_mismatch",
                (
                    "actual execution source is not at its canonical "
                    f"bundle path: {normalized_component}={relative_path}"
                ),
            )
        if relative_path in seen_paths:
            raise EvaluationContractError(
                "candidate_identity_execution_sources_invalid",
                (
                    "multiple candidate execution components resolve to "
                    f"the same source: {relative_path}"
                ),
            )
        seen_paths.add(relative_path)
        manifest_entry = manifest_by_path.get(relative_path)
        digest = (
            manifest_entry.get("sha256")
            if isinstance(manifest_entry, Mapping)
            else None
        )
        if not isinstance(digest, str) or len(digest) != 64:
            raise EvaluationContractError(
                "candidate_identity_execution_bundle_mismatch",
                (
                    "actual execution source is absent from the hashed "
                    f"candidate bundle: {normalized_component}"
                ),
            )
        bindings.append(
            {
                "component": normalized_component,
                "path": relative_path,
                "sha256": digest,
            }
        )
    return bindings


def _candidate_execution_component_paths(
    component: str,
) -> frozenset[str]:
    fixed = {
        "entrypoint.run_qa_cycle": frozenset({"run_qa_cycle.py"}),
        "runner.playwright_probe": frozenset(
            {"playwright_probe.mjs"}
        ),
        "qa_common": frozenset({"qa_common.py"}),
        "qa_core": frozenset({"qa_core/__init__.py"}),
        "qa_eval": frozenset({"qa_eval/__init__.py"}),
    }
    if component in fixed:
        return fixed[component]
    if component.startswith("qa_core.") or component.startswith(
        "qa_eval."
    ):
        relative = component.replace(".", "/")
        return frozenset(
            {
                f"{relative}.py",
                f"{relative}/__init__.py",
            }
        )
    return frozenset()


def _walk_evaluator_bundle(
    directory_fd: int,
    *,
    relative_parts: tuple[str, ...],
    depth: int,
    entries: list[dict[str, Any]],
    seen_files: set[tuple[int, int]],
    total_bytes: int,
) -> int:
    if depth > _MAX_EVALUATOR_BUNDLE_DEPTH:
        raise EvaluationContractError(
            "production_evaluator_bundle_depth_exceeded",
            "evaluator bundle directory depth exceeds the production limit",
        )
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise EvaluationContractError(
            "production_evaluator_bundle_read_failed",
            "cannot enumerate evaluator bundle directory",
        ) from exc
    for name in names:
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
        ):
            raise EvaluationContractError(
                "production_evaluator_bundle_name_invalid",
                "evaluator bundle contains a non-canonical entry name",
            )
        try:
            metadata = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise EvaluationContractError(
                "production_evaluator_bundle_read_failed",
                f"cannot inspect evaluator bundle entry: {name}",
            ) from exc
        relative = (*relative_parts, name)
        if stat.S_ISLNK(metadata.st_mode):
            raise EvaluationContractError(
                "production_evaluator_bundle_symlink_rejected",
                f"evaluator bundle contains symlink: {'/'.join(relative)}",
            )
        if stat.S_ISDIR(metadata.st_mode):
            child_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                child_fd = os.open(
                    name,
                    child_flags,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise EvaluationContractError(
                    "production_evaluator_bundle_read_failed",
                    (
                        "cannot open evaluator bundle directory: "
                        f"{'/'.join(relative)}"
                    ),
                ) from exc
            try:
                total_bytes = _walk_evaluator_bundle(
                    child_fd,
                    relative_parts=relative,
                    depth=depth + 1,
                    entries=entries,
                    seen_files=seen_files,
                    total_bytes=total_bytes,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise EvaluationContractError(
                "production_evaluator_bundle_non_regular",
                (
                    "evaluator bundle may contain only directories and "
                    f"regular files: {'/'.join(relative)}"
                ),
            )
        if metadata.st_nlink != 1:
            raise EvaluationContractError(
                "production_evaluator_bundle_hardlink_rejected",
                f"evaluator bundle file has aliases: {'/'.join(relative)}",
            )
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen_files:
            raise EvaluationContractError(
                "production_evaluator_bundle_alias_rejected",
                f"evaluator bundle file is aliased: {'/'.join(relative)}",
            )
        seen_files.add(identity)
        if len(entries) >= _MAX_EVALUATOR_BUNDLE_FILES:
            raise EvaluationContractError(
                "production_evaluator_bundle_file_limit_exceeded",
                "evaluator bundle exceeds the production file-count limit",
            )
        if metadata.st_size > _MAX_EVALUATOR_BUNDLE_FILE_BYTES:
            raise EvaluationContractError(
                "production_evaluator_bundle_file_too_large",
                f"evaluator bundle file is too large: {'/'.join(relative)}",
            )
        total_bytes += metadata.st_size
        if total_bytes > _MAX_EVALUATOR_BUNDLE_BYTES:
            raise EvaluationContractError(
                "production_evaluator_bundle_too_large",
                "evaluator bundle exceeds the production byte limit",
            )
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            file_fd = os.open(name, file_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise EvaluationContractError(
                "production_evaluator_bundle_read_failed",
                f"cannot open evaluator bundle file: {'/'.join(relative)}",
            ) from exc
        try:
            before = os.fstat(file_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != identity
                or before.st_size != metadata.st_size
            ):
                raise EvaluationContractError(
                    "production_evaluator_bundle_changed",
                    (
                        "evaluator bundle entry changed while opening: "
                        f"{'/'.join(relative)}"
                    ),
                )
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise EvaluationContractError(
                        "production_evaluator_bundle_truncated",
                        (
                            "evaluator bundle file truncated while reading: "
                            f"{'/'.join(relative)}"
                        ),
                    )
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_fd)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mode,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_nlink,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mode,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_nlink,
            ):
                raise EvaluationContractError(
                    "production_evaluator_bundle_changed",
                    (
                        "evaluator bundle file changed while reading: "
                        f"{'/'.join(relative)}"
                    ),
                )
        finally:
            os.close(file_fd)
        entries.append(
            {
                "path": "/".join(relative),
                "size": before.st_size,
                "mode": stat.S_IMODE(before.st_mode),
                "sha256": digest.hexdigest(),
            }
        )
    return total_bytes


def _verify_candidate_identity(
    observations: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> None:
    field_map = {
        "agent_bundle_sha256": "agent_bundle_hash",
        "policy_sha256": "policy_hash",
        "tool_registry_sha256": "tool_registry_hash",
        "memory_snapshot_sha256": "memory_snapshot_hash",
    }
    for signed_name, input_name in field_map.items():
        signed_value = _sha256(
            f"registration.candidate.{signed_name}",
            identity[signed_name],
        )
        if signed_value != observations.get(input_name):
            raise EvaluationContractError(
                "production_candidate_identity_mismatch",
                (
                    f"registration.candidate.{signed_name} must match "
                    f"observations.{input_name}"
                ),
            )
    if _text(
        "registration.candidate.model_id",
        identity["model_id"],
    ) != observations.get("model_id"):
        raise EvaluationContractError(
            "production_candidate_identity_mismatch",
            "signed candidate model_id must match observations.model_id",
        )


def _verify_baseline_identity(
    baseline: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> None:
    field_map = {
        "agent_bundle_sha256": "agent_bundle_hash",
        "policy_sha256": "policy_hash",
        "tool_registry_sha256": "tool_registry_hash",
    }
    for signed_name, input_name in field_map.items():
        signed_value = _sha256(
            f"registration.baseline.{signed_name}",
            identity[signed_name],
        )
        if signed_value != baseline.get(input_name):
            raise EvaluationContractError(
                "production_baseline_identity_mismatch",
                (
                    f"registration.baseline.{signed_name} must match "
                    f"baseline.{input_name}"
                ),
            )


def _trusted_public_key(
    trust_config: Mapping[str, Any],
    *,
    authority: str,
    key_id: str,
    suite_id: str,
    registration_issued_at: datetime,
    now: datetime,
) -> Ed25519PublicKey:
    root = _strict_object(
        "trust_config",
        trust_config,
        required={
            "schema_version",
            "checked_at",
            "expires_at",
            "trusted_evaluators",
        },
    )
    if root["schema_version"] != _TRUST_SCHEMA_VERSION:
        raise EvaluationContractError(
            "production_trust_schema_unsupported",
            (
                "trust_config.schema_version must equal "
                f"{_TRUST_SCHEMA_VERSION}"
            ),
        )
    checked_at = _timestamp("trust_config.checked_at", root["checked_at"])
    expires_at = _timestamp("trust_config.expires_at", root["expires_at"])
    if checked_at > now:
        raise EvaluationContractError(
            "production_trust_checked_in_future",
            "trust_config.checked_at must not be later than trusted now",
        )
    if now >= expires_at:
        raise EvaluationContractError(
            "production_trust_snapshot_expired",
            "trusted evaluator revocation snapshot is expired",
        )
    if now - checked_at > _MAX_TRUST_SNAPSHOT_AGE:
        raise EvaluationContractError(
            "production_trust_snapshot_stale",
            "trusted evaluator revocation snapshot is older than 24 hours",
        )
    if (
        expires_at <= checked_at
        or expires_at - checked_at > _MAX_TRUST_SNAPSHOT_HORIZON
    ):
        raise EvaluationContractError(
            "production_trust_snapshot_window_invalid",
            "trust snapshot lifetime must be positive and at most 24 hours",
        )
    entries = root["trusted_evaluators"]
    if not isinstance(entries, list) or not entries:
        raise EvaluationContractError(
            "production_trust_invalid",
            "trust_config.trusted_evaluators must be a non-empty list",
        )
    matched: dict[str, Any] | None = None
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(entries):
        entry = _strict_object(
            f"trust_config.trusted_evaluators[{index}]",
            raw,
            required={
                "authority",
                "key_id",
                "algorithm",
                "public_key_pem",
                "suite_ids",
                "purpose",
                "valid_from",
                "valid_until",
                "revoked",
            },
        )
        entry_authority = _text(
            f"trust_config.trusted_evaluators[{index}].authority",
            entry["authority"],
        )
        entry_key_id = _text(
            f"trust_config.trusted_evaluators[{index}].key_id",
            entry["key_id"],
        )
        identity = (entry_authority, entry_key_id)
        if identity in seen:
            raise EvaluationContractError(
                "production_trust_duplicate",
                "trusted evaluator authority/key_id entries must be unique",
            )
        seen.add(identity)
        if identity == (authority, key_id):
            matched = entry
    if matched is None:
        raise EvaluationContractError(
            "production_evaluator_untrusted",
            "registration authority/key_id is not in the trust allowlist",
        )
    if matched["algorithm"] != "Ed25519":
        raise EvaluationContractError(
            "production_trust_algorithm_invalid",
            "trusted evaluator algorithm must equal Ed25519",
        )
    if matched["purpose"] != "qa_agent_production_evaluator":
        raise EvaluationContractError(
            "production_trust_purpose_invalid",
            (
                "trusted evaluator key purpose must equal "
                "qa_agent_production_evaluator"
            ),
        )
    if not isinstance(matched["revoked"], bool):
        raise EvaluationContractError(
            "production_trust_revocation_invalid",
            "trusted evaluator revoked must be boolean",
        )
    if matched["revoked"]:
        raise EvaluationContractError(
            "production_evaluator_key_revoked",
            "trusted evaluator key is revoked",
        )
    valid_from = _timestamp(
        "trust_config.trusted_evaluator.valid_from",
        matched["valid_from"],
    )
    valid_until = _timestamp(
        "trust_config.trusted_evaluator.valid_until",
        matched["valid_until"],
    )
    if (
        valid_until <= valid_from
        or registration_issued_at < valid_from
        or registration_issued_at >= valid_until
        or now < valid_from
        or now >= valid_until
    ):
        raise EvaluationContractError(
            "production_evaluator_key_outside_validity",
            (
                "registration issued_at and trusted now must both be inside "
                "the evaluator key validity"
            ),
        )
    suite_ids = matched["suite_ids"]
    if (
        not isinstance(suite_ids, list)
        or not suite_ids
        or any(not isinstance(item, str) or not item for item in suite_ids)
        or len(suite_ids) != len(set(suite_ids))
    ):
        raise EvaluationContractError(
            "production_trust_suite_ids_invalid",
            "trusted evaluator suite_ids must be unique non-empty strings",
        )
    if suite_id not in suite_ids:
        raise EvaluationContractError(
            "production_evaluator_suite_untrusted",
            "trusted evaluator key is not allowlisted for this suite_id",
        )
    encoded = matched["public_key_pem"]
    if not isinstance(encoded, str):
        raise EvaluationContractError(
            "production_public_key_invalid",
            "trusted evaluator public_key_pem must be text",
        )
    try:
        key = serialization.load_pem_public_key(encoded.encode("ascii"))
    except (UnicodeEncodeError, TypeError, ValueError) as exc:
        raise EvaluationContractError(
            "production_public_key_invalid",
            "trusted evaluator public_key_pem is invalid",
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EvaluationContractError(
            "production_public_key_algorithm_invalid",
            "trusted evaluator public key must be Ed25519",
        )
    return key


def _trusted_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise EvaluationContractError(
            "production_verification_time_invalid",
            "trusted now must be a timezone-aware UTC datetime",
        )
    return value.astimezone(UTC)


def _budget_contract_sha256(manifest: Mapping[str, Any]) -> str:
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise EvaluationContractError(
            "production_budget_contract_invalid",
            "manifest.cases must be a list",
        )
    contract = [
        {
            "scenario_id": case.get("scenario_id"),
            "seed": case.get("seed"),
            "budget": case.get("budget"),
        }
        for case in cases
        if isinstance(case, Mapping)
    ]
    if len(contract) != len(cases):
        raise EvaluationContractError(
            "production_budget_contract_invalid",
            "every manifest case must be an object",
        )
    return _canonical_sha256(contract)


def _strict_object(
    name: str,
    value: Any,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvaluationContractError(
            "type_invalid",
            f"{name} must be an object",
        )
    normalized = dict(value)
    missing = sorted(required - set(normalized))
    unknown = sorted(set(normalized) - required - (optional or set()))
    if missing or unknown:
        raise EvaluationContractError(
            "fields_invalid",
            f"{name} fields invalid: missing={missing}, unknown={unknown}",
        )
    try:
        json.dumps(normalized, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvaluationContractError(
            "json_invalid",
            f"{name} must be JSON-compatible",
        ) from exc
    return normalized


def _text(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
    ):
        raise EvaluationContractError(
            "text_invalid",
            f"{name} must be canonical non-empty text",
        )
    return value


def _sha256(name: str, value: Any) -> str:
    normalized = _text(name, value)
    if len(normalized) != 64:
        raise EvaluationContractError(
            "sha256_invalid",
            f"{name} must be a 64-character SHA-256 digest",
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise EvaluationContractError(
            "sha256_invalid",
            f"{name} must be hexadecimal",
        ) from exc
    if normalized != normalized.lower():
        raise EvaluationContractError(
            "sha256_invalid",
            f"{name} must use lowercase hexadecimal",
        )
    return normalized


def _timestamp(name: str, value: Any) -> datetime:
    normalized = _text(name, value)
    if not normalized.endswith("Z"):
        raise EvaluationContractError(
            "timestamp_invalid",
            f"{name} must be an RFC3339 UTC timestamp ending in Z",
        )
    try:
        parsed = datetime.fromisoformat(
            normalized.removesuffix("Z") + "+00:00",
        )
    except ValueError as exc:
        raise EvaluationContractError(
            "timestamp_invalid",
            f"{name} must be an RFC3339 UTC timestamp",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvaluationContractError(
            "timestamp_invalid",
            f"{name} must use UTC",
        )
    return parsed


def _signature(value: Any) -> bytes:
    normalized = _text("registration.signature", value)
    try:
        decoded = base64.b64decode(
            normalized + "=" * (-len(normalized) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise EvaluationContractError(
            "production_registration_signature_invalid",
            "registration.signature must be canonical base64url",
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != 64 or canonical != normalized:
        raise EvaluationContractError(
            "production_registration_signature_invalid",
            "registration.signature must be a canonical Ed25519 signature",
        )
    return decoded


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()
