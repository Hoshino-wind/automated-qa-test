"""把现有 QA cycle 输出提交为带父哈希的不可变 attempt。"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping

from qa_core.contracts.artifacts import ARTIFACT_FILENAMES, INPUT_ARTIFACTS

from .attempts import (
    ArtifactRef,
    AttemptManifest,
    AttemptStore,
    AttemptStoreError,
    ManifestConflictError,
    StaleGenerationError,
)
from .lease import RunLease
from .session import LEASE_FILENAME

__all__ = [
    "CYCLE_OUTPUT_NAMES",
    "CycleAttemptError",
    "CycleAttemptResult",
    "commit_cycle_attempt",
]

CYCLE_OUTPUT_NAMES = frozenset(ARTIFACT_FILENAMES) - INPUT_ARTIFACTS
_COPY_CHUNK_SIZE = 1024 * 1024


class CycleAttemptError(RuntimeError):
    """Cycle 到 Attempt Store 适配边界的结构化失败。"""

    def __init__(
        self,
        code: str,
        phase: str,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.phase = phase
        self.details = MappingProxyType(dict(details or {}))
        super().__init__(message)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": "error",
            "error": "cycle_attempt_error",
            "code": self.code,
            "phase": self.phase,
            "message": str(self),
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class CycleAttemptResult:
    """一次成功 commit 与 run-manifest 发布的稳定回执。"""

    attempt: AttemptManifest
    run_manifest_sequence: int
    run_manifest_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": "committed",
            "run_id": self.attempt.run_id,
            "generation": self.attempt.generation,
            "iteration": self.attempt.iteration,
            "stage": self.attempt.stage,
            "tool": self.attempt.tool,
            "input_hashes": dict(self.attempt.input_hashes),
            "attempt_id": self.attempt.attempt_id,
            "attempt_manifest_sha256": self.attempt.manifest_sha256,
            "run_manifest_sequence": self.run_manifest_sequence,
            "run_manifest_sha256": self.run_manifest_sha256,
            "artifacts": [artifact.to_dict() for artifact in self.attempt.artifacts],
        }


def commit_cycle_attempt(
    *,
    run_dir: str | os.PathLike[str],
    run_id: str,
    lease_owner: str,
    generation: int,
    iteration: int,
    stage: str,
    tool: str,
    input_hashes: Mapping[str, str],
    expected_sequence: int,
    output_names: Iterable[str],
    current_artifacts: Iterable[str | os.PathLike[str]],
) -> CycleAttemptResult:
    """选择白名单 cycle 输出，commit 后以 expected_sequence 原子发布。"""
    resolved_run_dir = Path(run_dir).expanduser().resolve()
    try:
        _require_active_lease(
            resolved_run_dir,
            run_id=run_id,
            owner=lease_owner,
            generation=generation,
        )
    except Exception as error:
        raise _wrapped_error(
            "cycle_lease_invalid",
            "lease_preflight",
            error,
        ) from error
    try:
        if (
            isinstance(expected_sequence, bool)
            or not isinstance(expected_sequence, int)
            or expected_sequence < 0
        ):
            raise ValueError("expected_sequence 必须是非负整数")
        selected = _selected_outputs(resolved_run_dir, output_names)
        _require_current_outputs(selected, current_artifacts)
        _validate_sources(resolved_run_dir, selected)
    except Exception as error:
        raise _wrapped_error(
            "cycle_output_invalid",
            "select_outputs",
            error,
        ) from error

    store = AttemptStore(resolved_run_dir)
    try:
        current = store.read_run_manifest()
        retained = _retained_attempts(
            store,
            current=current,
            run_id=run_id,
            generation=generation,
            expected_sequence=expected_sequence,
        )
    except Exception as error:
        raise _wrapped_error(
            "cycle_manifest_preflight_failed",
            "manifest_preflight",
            error,
        ) from error

    try:
        _require_active_lease(
            resolved_run_dir,
            run_id=run_id,
            owner=lease_owner,
            generation=generation,
        )
        handle = store.begin(
            run_id=run_id,
            generation=generation,
            iteration=iteration,
            stage=stage,
            tool=tool,
            input_hashes=input_hashes,
        )
    except Exception as error:
        raise _wrapped_error("cycle_attempt_begin_failed", "begin", error) from error

    expected_artifacts: dict[str, tuple[str, int]] = {}
    try:
        for _, source in selected:
            scratch_path = handle.scratch_dir / source.name
            expected_artifacts[source.name] = _copy_regular_output(
                resolved_run_dir,
                source.name,
                scratch_path,
            )
    except Exception as error:
        raise _wrapped_error(
            "cycle_output_copy_failed",
            "copy_outputs",
            error,
            attempt_id=handle.attempt_id,
        ) from error

    try:
        _require_active_lease(
            resolved_run_dir,
            run_id=run_id,
            owner=lease_owner,
            generation=generation,
        )
        attempt = store.commit(
            handle,
            {
                source.name: handle.scratch_dir / source.name
                for _, source in selected
            },
        )
    except Exception as error:
        raise _wrapped_error(
            "cycle_attempt_commit_failed",
            "commit",
            error,
            attempt_id=handle.attempt_id,
        ) from error

    try:
        _verify_committed_artifacts(attempt.artifacts, expected_artifacts)
    except Exception as error:
        raise _wrapped_error(
            "cycle_artifact_verification_failed",
            "verify_commit",
            error,
            attempt_id=attempt.attempt_id,
            attempt_manifest_sha256=attempt.manifest_sha256,
        ) from error

    try:
        _require_active_lease(
            resolved_run_dir,
            run_id=run_id,
            owner=lease_owner,
            generation=generation,
        )
        published = store.publish_run_manifest(
            run_id=run_id,
            generation=generation,
            expected_sequence=expected_sequence,
            attempts=[*retained, attempt],
        )
    except Exception as error:
        raise _wrapped_error(
            "cycle_manifest_publish_failed",
            "publish_manifest",
            error,
            attempt_id=attempt.attempt_id,
            attempt_manifest_sha256=attempt.manifest_sha256,
        ) from error

    return CycleAttemptResult(
        attempt=attempt,
        run_manifest_sequence=int(published["sequence"]),
        run_manifest_sha256=str(published["manifest_sha256"]),
    )


def _require_active_lease(
    run_dir: Path,
    *,
    run_id: str,
    owner: str,
    generation: int,
) -> None:
    current = RunLease(run_dir / LEASE_FILENAME).read()
    if current is None:
        raise ValueError("cycle attempt requires an active run lease")
    if (
        current.run_id != run_id
        or current.owner != owner
        or current.generation != generation
    ):
        raise ValueError(
            "cycle attempt lease identity does not match the active writer"
        )


def _selected_outputs(
    run_dir: Path,
    output_names: Iterable[str],
) -> tuple[tuple[str, Path], ...]:
    if isinstance(output_names, (str, bytes)):
        raise ValueError("output_names 必须是输出名集合，不能是单个字符串")
    raw_names = tuple(output_names)
    if not raw_names:
        raise ValueError("output_names 不得为空")
    normalized: list[str] = []
    for value in raw_names:
        if not isinstance(value, str) or not value or value.strip() != value:
            raise ValueError("output name 必须是无首尾空白的非空字符串")
        if value not in CYCLE_OUTPUT_NAMES:
            raise ValueError(f"输出不在 cycle 白名单中：{value!r}")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise ValueError("output_names 不得重复")
    return tuple(
        (name, run_dir / ARTIFACT_FILENAMES[name])
        for name in sorted(normalized)
    )


def _validate_sources(run_dir: Path, selected: tuple[tuple[str, Path], ...]) -> None:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    directory_descriptor = os.open(run_dir, directory_flags)
    try:
        for _, source in selected:
            try:
                descriptor = os.open(source.name, file_flags, dir_fd=directory_descriptor)
            except OSError as error:
                raise ValueError(f"无法安全读取 cycle 输出：{source.name}: {error}") from error
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError(f"cycle 输出不是普通文件：{source.name}")
            finally:
                os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _require_current_outputs(
    selected: tuple[tuple[str, Path], ...],
    current_artifacts: Iterable[str | os.PathLike[str]],
) -> None:
    if isinstance(current_artifacts, (str, bytes, os.PathLike)):
        raise ValueError("current_artifacts 必须是路径集合")
    current = {
        Path(path).expanduser().resolve()
        for path in current_artifacts
    }
    stale = [
        str(source)
        for _, source in selected
        if source.resolve() not in current
    ]
    if stale:
        raise ValueError(f"所选输出未标记为本轮 current artifact：{', '.join(stale)}")


def _retained_attempts(
    store: AttemptStore,
    *,
    current: Mapping[str, object] | None,
    run_id: str,
    generation: int,
    expected_sequence: int,
) -> list[AttemptManifest]:
    if current is None:
        if expected_sequence != 0:
            raise ManifestConflictError(
                "sequence_conflict",
                f"expected_sequence={expected_sequence}，当前 sequence=0",
            )
        return []
    if current["run_id"] != run_id:
        raise ManifestConflictError("run_id_mismatch", "当前 run manifest 属于另一个 run_id")
    current_sequence = int(current["sequence"])
    if current_sequence != expected_sequence:
        raise ManifestConflictError(
            "sequence_conflict",
            f"expected_sequence={expected_sequence}，当前 sequence={current_sequence}",
        )
    current_generation = int(current["generation"])
    if generation < current_generation:
        raise StaleGenerationError(
            "stale_generation",
            f"generation {generation} 早于当前 {current_generation}",
        )
    if generation > current_generation + 1:
        raise ManifestConflictError(
            "generation_gap",
            f"generation 只能从 {current_generation} 保持或递增一代",
        )
    if generation != current_generation:
        return []
    references = current["attempts"]
    if not isinstance(references, list):
        raise ValueError("run manifest attempts 必须是数组")
    retained: list[AttemptManifest] = []
    for reference in references:
        if not isinstance(reference, dict) or set(reference) != {
            "attempt_id",
            "manifest_sha256",
        }:
            raise ValueError("run manifest attempt reference 格式非法")
        retained.append(store.load_attempt(str(reference["attempt_id"])))
    return retained


def _copy_regular_output(
    run_dir: Path,
    filename: str,
    destination: Path,
) -> tuple[str, int]:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    directory_descriptor = os.open(run_dir, directory_flags)
    source_descriptor = -1
    destination_descriptor = -1
    try:
        source_descriptor = os.open(filename, source_flags, dir_fd=directory_descriptor)
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"cycle 输出不是普通文件：{filename}")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
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
        if _fingerprint(before) != _fingerprint(after):
            raise ValueError(f"cycle 输出在复制期间发生变化：{filename}")
        return digest.hexdigest(), size
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        os.close(directory_descriptor)


def _verify_committed_artifacts(
    artifacts: tuple[ArtifactRef, ...],
    expected: Mapping[str, tuple[str, int]],
) -> None:
    observed = {
        artifact.name: (artifact.sha256, artifact.size)
        for artifact in artifacts
    }
    if observed != dict(expected):
        raise ValueError(
            f"committed artifact 哈希或大小不匹配：expected={dict(expected)!r}, observed={observed!r}"
        )


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
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


def _wrapped_error(
    code: str,
    phase: str,
    error: Exception,
    **details: object,
) -> CycleAttemptError:
    enriched = dict(details)
    enriched["cause_type"] = type(error).__name__
    if isinstance(error, AttemptStoreError):
        enriched["store_code"] = error.code
    return CycleAttemptError(
        code,
        phase,
        str(error),
        details=enriched,
    )
