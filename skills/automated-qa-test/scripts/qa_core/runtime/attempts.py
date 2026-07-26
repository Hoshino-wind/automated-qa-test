"""不可变 attempt 产物提交与运行 manifest 的代际 CAS。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Iterable, Iterator, Mapping, cast

__all__ = [
    "ArtifactRef",
    "AttemptAlreadyCommittedError",
    "AttemptHandle",
    "AttemptIntegrityError",
    "AttemptManifest",
    "AttemptNotCommittedError",
    "AttemptSourceError",
    "AttemptStore",
    "AttemptStoreError",
    "ManifestConflictError",
    "StaleGenerationError",
]

_ATTEMPT_SCHEMA_VERSION = 1
_RUN_MANIFEST_SCHEMA_VERSION = 1
_ATTEMPT_ID_PATTERN = re.compile(r"att_[0-9a-f]{32}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_COPY_CHUNK_SIZE = 1024 * 1024


class AttemptStoreError(RuntimeError):
    """Attempt Store 的结构化失败。"""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class AttemptAlreadyCommittedError(AttemptStoreError):
    """同一 attempt 已经完成提交。"""

    def __init__(self, attempt_id: str) -> None:
        super().__init__("attempt_already_committed", f"attempt 已提交且不得覆盖：{attempt_id}")


class AttemptNotCommittedError(AttemptStoreError):
    """Attempt 尚无权威提交。"""

    def __init__(self, attempt_id: str) -> None:
        super().__init__("attempt_not_committed", f"attempt 尚未提交：{attempt_id}")


class AttemptSourceError(AttemptStoreError):
    """Scratch 输入越界或不是可提交的普通文件。"""


class AttemptIntegrityError(AttemptStoreError):
    """已提交内容、manifest 或目录结构不再可信。"""


class ManifestConflictError(AttemptStoreError):
    """Run manifest 的比较交换前置条件不成立。"""


class StaleGenerationError(ManifestConflictError):
    """旧 generation 试图覆盖较新的运行视图。"""


@dataclass(frozen=True, slots=True)
class AttemptHandle:
    """`begin` 返回的单次 attempt 写入句柄。"""

    attempt_id: str
    run_id: str
    generation: int
    iteration: int
    stage: str
    tool: str
    input_hashes: Mapping[str, str]
    attempt_dir: Path
    scratch_dir: Path
    created_at: str


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """一个已提交文件的内容寻址引用。"""

    attempt_id: str
    name: str
    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: object) -> ArtifactRef:
        expected_fields = {"attempt_id", "name", "path", "sha256", "size"}
        payload = _strict_object(value, expected_fields, artifact="artifact ref")
        return cls(
            attempt_id=_attempt_id(payload["attempt_id"]),
            name=_artifact_name(payload["name"]),
            path=_relative_posix_path(payload["path"], field="artifact path"),
            sha256=_sha256(payload["sha256"], field="artifact sha256"),
            size=_nonnegative_int(payload["size"], field="artifact size"),
        )


@dataclass(frozen=True, slots=True)
class AttemptManifest:
    """一个已提交 attempt 的完整、可重算 manifest。"""

    attempt_id: str
    run_id: str
    generation: int
    iteration: int
    stage: str
    tool: str
    input_hashes: Mapping[str, str]
    created_at: str
    committed_at: str
    artifacts: tuple[ArtifactRef, ...]
    manifest_sha256: str
    schema_version: int = _ATTEMPT_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        attempt_id: str,
        run_id: str,
        generation: int,
        iteration: int,
        stage: str,
        tool: str,
        input_hashes: Mapping[str, str],
        created_at: str,
        committed_at: str,
        artifacts: Iterable[ArtifactRef],
    ) -> AttemptManifest:
        normalized_id = _attempt_id(attempt_id)
        ordered = tuple(sorted(artifacts, key=lambda item: item.name))
        _validate_artifact_refs(normalized_id, ordered)
        unsigned = {
            "schema_version": _ATTEMPT_SCHEMA_VERSION,
            "attempt_id": normalized_id,
            "run_id": _nonempty_text(run_id, field="run_id"),
            "generation": _positive_int(generation, field="generation"),
            "iteration": _positive_int(iteration, field="iteration"),
            "stage": _nonempty_text(stage, field="stage"),
            "tool": _nonempty_text(tool, field="tool"),
            "input_hashes": _input_hashes(input_hashes),
            "created_at": _timestamp(created_at, field="created_at"),
            "committed_at": _timestamp(committed_at, field="committed_at"),
            "artifacts": [item.to_dict() for item in ordered],
        }
        return cls(
            attempt_id=normalized_id,
            run_id=unsigned["run_id"],
            generation=unsigned["generation"],
            iteration=unsigned["iteration"],
            stage=unsigned["stage"],
            tool=unsigned["tool"],
            input_hashes=MappingProxyType(dict(unsigned["input_hashes"])),
            created_at=unsigned["created_at"],
            committed_at=unsigned["committed_at"],
            artifacts=ordered,
            manifest_sha256=_hash_json(unsigned),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "generation": self.generation,
            "iteration": self.iteration,
            "stage": self.stage,
            "tool": self.tool,
            "input_hashes": dict(self.input_hashes),
            "created_at": self.created_at,
            "committed_at": self.committed_at,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> AttemptManifest:
        expected_fields = {
            "schema_version",
            "attempt_id",
            "run_id",
            "generation",
            "iteration",
            "stage",
            "tool",
            "input_hashes",
            "created_at",
            "committed_at",
            "artifacts",
            "manifest_sha256",
        }
        payload = _strict_object(value, expected_fields, artifact="attempt manifest")
        if payload["schema_version"] != _ATTEMPT_SCHEMA_VERSION:
            raise AttemptIntegrityError("attempt_schema_invalid", "attempt manifest schema_version 不受支持")
        raw_artifacts = payload["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise AttemptIntegrityError("attempt_artifacts_invalid", "attempt manifest artifacts 必须是数组")
        manifest = cls.create(
            attempt_id=_attempt_id(payload["attempt_id"]),
            run_id=_nonempty_text(payload["run_id"], field="run_id"),
            generation=_positive_int(payload["generation"], field="generation"),
            iteration=_positive_int(payload["iteration"], field="iteration"),
            stage=_nonempty_text(payload["stage"], field="stage"),
            tool=_nonempty_text(payload["tool"], field="tool"),
            input_hashes=_input_hashes(payload["input_hashes"]),
            created_at=_timestamp(payload["created_at"], field="created_at"),
            committed_at=_timestamp(payload["committed_at"], field="committed_at"),
            artifacts=(ArtifactRef.from_dict(item) for item in raw_artifacts),
        )
        recorded_hash = _sha256(payload["manifest_sha256"], field="manifest_sha256")
        if manifest.manifest_sha256 != recorded_hash:
            raise AttemptIntegrityError("attempt_manifest_hash_mismatch", "attempt manifest 内容哈希不匹配")
        return manifest


class AttemptStore:
    """管理 scratch、不可变提交以及 run manifest CAS。"""

    def __init__(
        self,
        run_dir: str | os.PathLike[str],
    ) -> None:
        self.run_dir = Path(run_dir).expanduser().resolve()
        self.attempts_dir = self.run_dir / "attempts"
        self.run_manifest_path = self.run_dir / "run-manifest.json"
        self._run_manifest_guard_path = self.run_dir / ".run-manifest.guard"

    def begin(
        self,
        *,
        run_id: str,
        generation: int,
        iteration: int,
        stage: str,
        tool: str,
        input_hashes: Mapping[str, str],
    ) -> AttemptHandle:
        """原子占用不可预测 attempt_id，并创建仅属于该 attempt 的 scratch。"""
        authority: dict[str, object] = {
            "run_id": _nonempty_text(run_id, field="run_id"),
            "generation": _positive_int(generation, field="generation"),
            "iteration": _positive_int(iteration, field="iteration"),
            "stage": _nonempty_text(stage, field="stage"),
            "tool": _nonempty_text(tool, field="tool"),
            "input_hashes": _input_hashes(input_hashes),
        }
        self._ensure_roots()
        for _ in range(16):
            token = secrets.token_hex(16)
            attempt_id = f"att_{token}"
            attempt_dir = self.attempts_dir / attempt_id
            try:
                attempt_dir.mkdir(mode=0o700)
            except FileExistsError:
                continue

            created_at = _utc_now()
            scratch_dir = attempt_dir / "scratch"
            try:
                scratch_dir.mkdir(mode=0o700)
                _atomic_write_json(
                    attempt_dir / "attempt.json",
                    {
                        "schema_version": _ATTEMPT_SCHEMA_VERSION,
                        "attempt_id": attempt_id,
                        **authority,
                        "created_at": created_at,
                    },
                )
                _fsync_directory(attempt_dir)
                _fsync_directory(self.attempts_dir)
            except BaseException:
                _remove_tree(attempt_dir)
                _fsync_directory(self.attempts_dir)
                raise
            return AttemptHandle(
                attempt_id=attempt_id,
                run_id=authority["run_id"],
                generation=authority["generation"],
                iteration=authority["iteration"],
                stage=authority["stage"],
                tool=authority["tool"],
                input_hashes=MappingProxyType(dict(authority["input_hashes"])),
                attempt_dir=attempt_dir,
                scratch_dir=scratch_dir,
                created_at=created_at,
            )
        raise AttemptStoreError("attempt_id_exhausted", "连续 16 次 attempt_id 冲突")

    def commit(
        self,
        handle: AttemptHandle,
        artifacts: Mapping[str, str | os.PathLike[str]],
    ) -> AttemptManifest:
        """复制 scratch 内普通文件，并以 manifest 最后出现作为提交点。"""
        metadata = self._validate_handle(handle)
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise ValueError("artifacts 必须是非空映射")
        specifications = [
            (_artifact_name(name), _scratch_relative_path(handle, source))
            for name, source in artifacts.items()
        ]
        names = [name for name, _ in specifications]
        if len(names) != len(set(names)):
            raise ValueError("artifact name 不得重复")

        committed_dir = handle.attempt_dir / "committed"
        if _entry_exists(committed_dir):
            raise AttemptAlreadyCommittedError(handle.attempt_id)

        staging_dir = handle.attempt_dir / f".commit-{secrets.token_hex(16)}"
        staging_dir.mkdir(mode=0o700)
        published = False
        try:
            artifact_dir = staging_dir / "artifacts"
            artifact_dir.mkdir(mode=0o700)
            refs: list[ArtifactRef] = []
            for name, relative_source in sorted(specifications):
                destination = artifact_dir.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                refs.append(
                    self._copy_artifact(
                        handle,
                        name=name,
                        relative_source=relative_source,
                        destination=destination,
                    )
                )

            manifest = AttemptManifest.create(
                attempt_id=handle.attempt_id,
                run_id=handle.run_id,
                generation=handle.generation,
                iteration=handle.iteration,
                stage=handle.stage,
                tool=handle.tool,
                input_hashes=handle.input_hashes,
                created_at=metadata["created_at"],
                committed_at=_utc_now(),
                artifacts=refs,
            )
            _fsync_tree(artifact_dir)
            _atomic_write_json(staging_dir / "attempt-manifest.json", manifest.to_dict())
            _fsync_directory(staging_dir)
            try:
                os.rename(staging_dir, committed_dir)
            except OSError as error:
                if _entry_exists(committed_dir):
                    raise AttemptAlreadyCommittedError(handle.attempt_id) from error
                raise
            published = True
            _fsync_directory(handle.attempt_dir)
            return self.load_attempt(handle.attempt_id)
        finally:
            if not published:
                _remove_tree(staging_dir)

    def load_attempt(self, attempt_id: str) -> AttemptManifest:
        """重新校验 attempt manifest 和每个已提交文件。"""
        normalized_id = _attempt_id(attempt_id)
        attempt_dir = self.attempts_dir / normalized_id
        _require_directory(attempt_dir, code="attempt_missing")
        metadata = self._load_attempt_metadata(attempt_dir)
        if metadata["attempt_id"] != normalized_id:
            raise AttemptIntegrityError("attempt_id_mismatch", "attempt metadata 与目录名不一致")

        committed_dir = attempt_dir / "committed"
        if not _entry_exists(committed_dir):
            raise AttemptNotCommittedError(normalized_id)
        _require_directory(committed_dir, code="attempt_commit_not_directory")
        manifest = AttemptManifest.from_dict(
            _read_json(committed_dir / "attempt-manifest.json")
        )
        if manifest.attempt_id != normalized_id:
            raise AttemptIntegrityError("attempt_id_mismatch", "attempt manifest 与目录名不一致")
        if manifest.created_at != metadata["created_at"]:
            raise AttemptIntegrityError("attempt_created_at_mismatch", "attempt 创建时间被篡改")
        for field in ("run_id", "generation", "iteration", "stage", "tool", "input_hashes"):
            if getattr(manifest, field) != metadata[field]:
                raise AttemptIntegrityError(
                    "attempt_authority_mismatch",
                    f"attempt manifest 的 {field} 与权威父输入不一致",
                )

        for artifact in manifest.artifacts:
            expected_path = self._artifact_path(normalized_id, artifact.name)
            if artifact.path != expected_path:
                raise AttemptIntegrityError(
                    "artifact_path_mismatch",
                    f"artifact {artifact.name!r} 的路径未绑定到当前 attempt",
                )
            observed_hash, observed_size = _hash_file_beneath(
                self.run_dir,
                PurePosixPath(artifact.path),
            )
            if observed_hash != artifact.sha256 or observed_size != artifact.size:
                raise AttemptIntegrityError(
                    "artifact_hash_mismatch",
                    f"artifact {artifact.name!r} 的内容或大小被篡改",
                )
        return manifest

    def publish_run_manifest(
        self,
        *,
        run_id: str,
        generation: int,
        expected_sequence: int,
        attempts: Iterable[AttemptManifest],
    ) -> dict[str, object]:
        """以 sequence CAS 发布只引用已验证 attempt 哈希的运行视图。"""
        normalized_run_id = _nonempty_text(run_id, field="run_id")
        normalized_generation = _positive_int(generation, field="generation")
        normalized_sequence = _nonnegative_int(expected_sequence, field="expected_sequence")
        proposed_attempts = tuple(attempts)
        if not all(isinstance(item, AttemptManifest) for item in proposed_attempts):
            raise TypeError("attempts 必须只包含 AttemptManifest")

        self._ensure_roots()
        with self._run_manifest_guard():
            current = self._load_run_manifest_unlocked()
            if current is None:
                current_sequence = 0
                previous_hash: str | None = None
            else:
                self._verify_run_manifest_attempts(current)
                if current["run_id"] != normalized_run_id:
                    raise ManifestConflictError("run_id_mismatch", "run manifest 属于另一个 run_id")
                current_sequence = int(current["sequence"])
                previous_hash = str(current["manifest_sha256"])
                current_generation = int(current["generation"])
                if normalized_generation < current_generation:
                    raise StaleGenerationError(
                        "stale_generation",
                        f"generation {normalized_generation} 早于当前 {current_generation}",
                    )
                if normalized_generation > current_generation + 1:
                    raise ManifestConflictError(
                        "generation_gap",
                        f"generation 只能从 {current_generation} 保持或递增一代",
                    )

            if normalized_sequence != current_sequence:
                raise ManifestConflictError(
                    "sequence_conflict",
                    f"expected_sequence={normalized_sequence}，当前 sequence={current_sequence}",
                )

            references = self._verified_attempt_references(
                proposed_attempts,
                run_id=normalized_run_id,
                generation=normalized_generation,
            )
            unsigned: dict[str, object] = {
                "schema_version": _RUN_MANIFEST_SCHEMA_VERSION,
                "run_id": normalized_run_id,
                "generation": normalized_generation,
                "sequence": current_sequence + 1,
                "published_at": _utc_now(),
                "previous_manifest_sha256": previous_hash,
                "attempts": references,
            }
            published = {**unsigned, "manifest_sha256": _hash_json(unsigned)}
            _atomic_write_json(self.run_manifest_path, published)
            return published

    def read_run_manifest(self) -> dict[str, object] | None:
        """读取并验证当前 run manifest 及其所有 attempt 引用。"""
        self._ensure_roots()
        with self._run_manifest_guard():
            manifest = self._load_run_manifest_unlocked()
            if manifest is not None:
                self._verify_run_manifest_attempts(manifest)
            return manifest

    def _validate_handle(self, handle: AttemptHandle) -> dict[str, str | int]:
        if not isinstance(handle, AttemptHandle):
            raise TypeError("handle 必须是 AttemptHandle")
        normalized_id = _attempt_id(handle.attempt_id)
        expected_dir = self.attempts_dir / normalized_id
        if handle.attempt_dir != expected_dir or handle.scratch_dir != expected_dir / "scratch":
            raise AttemptSourceError("attempt_handle_foreign", "handle 不属于当前 AttemptStore")
        _require_directory(expected_dir, code="attempt_missing")
        _require_directory(handle.scratch_dir, code="scratch_missing")
        metadata = self._load_attempt_metadata(expected_dir)
        if (
            metadata["attempt_id"] != normalized_id
            or metadata["created_at"] != handle.created_at
        ):
            raise AttemptIntegrityError("attempt_handle_mismatch", "handle 与磁盘 attempt metadata 不一致")
        for field in ("run_id", "generation", "iteration", "stage", "tool", "input_hashes"):
            if getattr(handle, field) != metadata[field]:
                raise AttemptIntegrityError(
                    "attempt_handle_authority_mismatch",
                    f"handle 的 {field} 与权威父输入不一致",
                )
        return metadata

    def _load_attempt_metadata(self, attempt_dir: Path) -> dict[str, object]:
        payload = _strict_object(
            _read_json(attempt_dir / "attempt.json"),
            {
                "schema_version",
                "attempt_id",
                "run_id",
                "generation",
                "iteration",
                "stage",
                "tool",
                "input_hashes",
                "created_at",
            },
            artifact="attempt metadata",
        )
        if payload["schema_version"] != _ATTEMPT_SCHEMA_VERSION:
            raise AttemptIntegrityError("attempt_schema_invalid", "attempt metadata schema_version 不受支持")
        return {
            "schema_version": _ATTEMPT_SCHEMA_VERSION,
            "attempt_id": _attempt_id(payload["attempt_id"]),
            "run_id": _nonempty_text(payload["run_id"], field="run_id"),
            "generation": _positive_int(payload["generation"], field="generation"),
            "iteration": _positive_int(payload["iteration"], field="iteration"),
            "stage": _nonempty_text(payload["stage"], field="stage"),
            "tool": _nonempty_text(payload["tool"], field="tool"),
            "input_hashes": _input_hashes(payload["input_hashes"]),
            "created_at": _timestamp(payload["created_at"], field="created_at"),
        }

    def _copy_artifact(
        self,
        handle: AttemptHandle,
        *,
        name: str,
        relative_source: PurePosixPath,
        destination: Path,
    ) -> ArtifactRef:
        source_descriptor = _open_regular_beneath(handle.scratch_dir, relative_source)
        destination_descriptor = -1
        try:
            before = os.fstat(source_descriptor)
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o400,
            )
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(source_descriptor, _COPY_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                _write_all(destination_descriptor, chunk)
            os.fsync(destination_descriptor)
            after = os.fstat(source_descriptor)
            if _source_fingerprint(before) != _source_fingerprint(after):
                raise AttemptSourceError(
                    "artifact_changed_during_commit",
                    f"scratch 文件在提交期间发生变化：{relative_source}",
                )
            os.close(destination_descriptor)
            destination_descriptor = -1
            return ArtifactRef(
                attempt_id=handle.attempt_id,
                name=name,
                path=self._artifact_path(handle.attempt_id, name),
                sha256=digest.hexdigest(),
                size=size,
            )
        except BaseException:
            if destination_descriptor >= 0:
                os.close(destination_descriptor)
            destination.unlink(missing_ok=True)
            raise
        finally:
            os.close(source_descriptor)

    def _artifact_path(self, attempt_id: str, name: str) -> str:
        return str(
            PurePosixPath("attempts")
            / _attempt_id(attempt_id)
            / "committed"
            / "artifacts"
            / _artifact_name(name)
        )

    def _verified_attempt_references(
        self,
        attempts: Iterable[AttemptManifest],
        *,
        run_id: str,
        generation: int,
    ) -> list[dict[str, str]]:
        references: list[dict[str, str]] = []
        seen: set[str] = set()
        for proposed in attempts:
            if proposed.attempt_id in seen:
                raise ValueError(f"attempts 含重复 attempt_id：{proposed.attempt_id}")
            seen.add(proposed.attempt_id)
            committed = self.load_attempt(proposed.attempt_id)
            if committed != proposed:
                raise AttemptIntegrityError(
                    "attempt_manifest_reference_mismatch",
                    f"提交引用与磁盘 manifest 不一致：{proposed.attempt_id}",
                )
            if committed.run_id != run_id or committed.generation != generation:
                raise AttemptIntegrityError(
                    "attempt_authority_mismatch",
                    f"attempt {proposed.attempt_id} 不属于 run_id={run_id!r}, generation={generation}",
                )
            references.append(
                {
                    "attempt_id": committed.attempt_id,
                    "manifest_sha256": committed.manifest_sha256,
                }
            )
        return sorted(references, key=lambda item: item["attempt_id"])

    def _load_run_manifest_unlocked(self) -> dict[str, object] | None:
        if not _entry_exists(self.run_manifest_path):
            return None
        expected_fields = {
            "schema_version",
            "run_id",
            "generation",
            "sequence",
            "published_at",
            "previous_manifest_sha256",
            "attempts",
            "manifest_sha256",
        }
        payload = _strict_object(
            _read_json(self.run_manifest_path),
            expected_fields,
            artifact="run manifest",
        )
        if payload["schema_version"] != _RUN_MANIFEST_SCHEMA_VERSION:
            raise AttemptIntegrityError("run_manifest_schema_invalid", "run manifest schema_version 不受支持")
        run_id = _nonempty_text(payload["run_id"], field="run_id")
        generation = _positive_int(payload["generation"], field="generation")
        sequence = _positive_int(payload["sequence"], field="sequence")
        published_at = _timestamp(payload["published_at"], field="published_at")
        previous_hash = payload["previous_manifest_sha256"]
        if previous_hash is not None:
            previous_hash = _sha256(previous_hash, field="previous_manifest_sha256")
        references = _run_attempt_references(payload["attempts"])
        unsigned: dict[str, object] = {
            "schema_version": _RUN_MANIFEST_SCHEMA_VERSION,
            "run_id": run_id,
            "generation": generation,
            "sequence": sequence,
            "published_at": published_at,
            "previous_manifest_sha256": previous_hash,
            "attempts": references,
        }
        recorded_hash = _sha256(payload["manifest_sha256"], field="manifest_sha256")
        if _hash_json(unsigned) != recorded_hash:
            raise AttemptIntegrityError("run_manifest_hash_mismatch", "run manifest 内容哈希不匹配")
        return {**unsigned, "manifest_sha256": recorded_hash}

    def _verify_run_manifest_attempts(self, manifest: Mapping[str, object]) -> None:
        references = cast(list[dict[str, str]], manifest["attempts"])
        for reference in references:
            attempt_id = reference["attempt_id"]
            committed = self.load_attempt(attempt_id)
            if committed.manifest_sha256 != reference["manifest_sha256"]:
                raise AttemptIntegrityError(
                    "run_attempt_hash_mismatch",
                    f"run manifest 的 attempt 哈希失效：{attempt_id}",
                )
            if (
                committed.run_id != manifest["run_id"]
                or committed.generation != manifest["generation"]
            ):
                raise AttemptIntegrityError(
                    "run_attempt_authority_mismatch",
                    f"run manifest 引用了其他 run 或 generation 的 attempt：{attempt_id}",
                )

    def _ensure_roots(self) -> None:
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.attempts_dir.mkdir(mode=0o700, exist_ok=True)

    @contextmanager
    def _run_manifest_guard(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._run_manifest_guard_path, flags, 0o600)
        locked = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            yield
        finally:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        # guard inode 必须持久存在；删除会让并发者锁住不同 inode。


def _validate_artifact_refs(attempt_id: str, artifacts: tuple[ArtifactRef, ...]) -> None:
    if not artifacts:
        raise AttemptIntegrityError("attempt_artifacts_empty", "attempt manifest 至少需要一个 artifact")
    seen: set[str] = set()
    for artifact in artifacts:
        if artifact.attempt_id != attempt_id:
            raise AttemptIntegrityError("artifact_attempt_mismatch", "artifact ref 属于另一个 attempt")
        if artifact.name in seen:
            raise AttemptIntegrityError("artifact_name_duplicate", f"artifact name 重复：{artifact.name}")
        seen.add(artifact.name)


def _run_attempt_references(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise AttemptIntegrityError("run_attempts_invalid", "run manifest attempts 必须是数组")
    references: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        payload = _strict_object(
            item,
            {"attempt_id", "manifest_sha256"},
            artifact="run attempt reference",
        )
        attempt_id = _attempt_id(payload["attempt_id"])
        if attempt_id in seen:
            raise AttemptIntegrityError("run_attempt_duplicate", f"run manifest 重复引用 {attempt_id}")
        seen.add(attempt_id)
        references.append(
            {
                "attempt_id": attempt_id,
                "manifest_sha256": _sha256(payload["manifest_sha256"], field="manifest_sha256"),
            }
        )
    if references != sorted(references, key=lambda item: item["attempt_id"]):
        raise AttemptIntegrityError("run_attempt_order_invalid", "run manifest attempts 必须按 attempt_id 排序")
    return references


def _scratch_relative_path(
    handle: AttemptHandle,
    source: str | os.PathLike[str],
) -> PurePosixPath:
    raw = Path(source)
    if raw.is_absolute():
        try:
            raw = raw.relative_to(handle.scratch_dir)
        except ValueError as error:
            raise AttemptSourceError("artifact_outside_scratch", f"artifact 越过 scratch：{source}") from error
    parts = raw.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AttemptSourceError("artifact_path_invalid", f"scratch 相对路径非法：{source}")
    return PurePosixPath(*parts)


def _artifact_name(value: object) -> str:
    text = _nonempty_text(value, field="artifact name")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"artifact name 必须是安全相对路径：{text!r}")
    if str(path) != text or "\\" in text:
        raise ValueError(f"artifact name 必须使用规范 POSIX 相对路径：{text!r}")
    return text


def _relative_posix_path(value: object, *, field: str) -> str:
    text = _nonempty_text(value, field=field)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AttemptIntegrityError("relative_path_invalid", f"{field} 必须是安全相对路径")
    if str(path) != text or "\\" in text:
        raise AttemptIntegrityError("relative_path_invalid", f"{field} 必须使用规范 POSIX 相对路径")
    return text


def _open_regular_beneath(root: Path, relative: PurePosixPath) -> int:
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AttemptSourceError("artifact_path_invalid", f"文件路径非法：{relative}")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags |= getattr(os, "O_NONBLOCK", 0)
    directory_descriptors: list[int] = []
    file_descriptor = -1
    try:
        directory_descriptors.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            directory_descriptors.append(
                os.open(part, directory_flags, dir_fd=directory_descriptors[-1])
            )
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptors[-1])
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AttemptSourceError("artifact_not_regular", f"仅允许普通文件：{relative}")
        return file_descriptor
    except AttemptStoreError:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        raise
    except OSError as error:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        raise AttemptSourceError("artifact_unreadable", f"无法安全读取文件 {relative}: {error}") from error
    finally:
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)


def _hash_file_beneath(root: Path, relative: PurePosixPath) -> tuple[str, int]:
    try:
        descriptor = _open_regular_beneath(root, relative)
    except AttemptSourceError as error:
        raise AttemptIntegrityError("artifact_unreadable", str(error)) from error
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _source_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("文件写入未取得进展")
        offset += written


def _atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(raw_temporary)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AttemptIntegrityError("json_unreadable", f"无法安全读取 JSON {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AttemptIntegrityError("json_not_regular", f"JSON 路径不是普通文件：{path}")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_JSON_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_JSON_BYTES:
                raise AttemptIntegrityError("json_too_large", f"JSON 超过 {_MAX_JSON_BYTES} 字节：{path}")
    finally:
        os.close(descriptor)
    try:
        return json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttemptIntegrityError("json_invalid", f"JSON 无效 {path}: {error}") from error


def _strict_object(
    value: object,
    expected_fields: set[str],
    *,
    artifact: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AttemptIntegrityError("json_not_object", f"{artifact} 必须是 JSON 对象")
    if set(value) != expected_fields:
        missing = sorted(expected_fields - set(value))
        extra = sorted(set(value) - expected_fields)
        raise AttemptIntegrityError(
            "json_fields_invalid",
            f"{artifact} 字段不匹配：missing={missing}, extra={extra}",
        )
    return value


def _hash_json(value: Mapping[str, object]) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _attempt_id(value: object) -> str:
    if not isinstance(value, str) or not _ATTEMPT_ID_PATTERN.fullmatch(value):
        raise AttemptIntegrityError("attempt_id_invalid", "attempt_id 格式非法")
    return value


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise AttemptIntegrityError("sha256_invalid", f"{field} 必须是小写 SHA-256")
    return value


def _input_hashes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("input_hashes 必须是非空 name→SHA256 映射")
    normalized: dict[str, str] = {}
    for raw_name, raw_hash in value.items():
        name = _nonempty_text(raw_name, field="input_hashes name")
        if name != raw_name or name in normalized:
            raise ValueError("input_hashes name 必须唯一且不得包含首尾空白")
        normalized[name] = _sha256(raw_hash, field=f"input_hashes.{name}")
    return dict(sorted(normalized.items()))


def _nonempty_text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} 必须是非空字符串")
    return value.strip()


def _positive_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} 必须是正整数")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} 必须是非负整数")
    return value


def _timestamp(value: object, *, field: str) -> str:
    text = _nonempty_text(value, field=field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} 必须是 RFC3339 时间") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} 必须包含时区")
    return text


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _entry_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _require_directory(path: Path, *, code: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise AttemptIntegrityError(code, f"目录不存在：{path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise AttemptIntegrityError(code, f"路径不是可信目录：{path}")


def _fsync_tree(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in reversed(directories):
        _fsync_directory(directory)
    _fsync_directory(root)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_tree(path: Path) -> None:
    if _entry_exists(path):
        shutil.rmtree(path)
