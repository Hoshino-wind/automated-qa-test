"""Bounded, alias-aware JSON input snapshots for evaluation CLIs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .scoring import EvaluationContractError


@dataclass(frozen=True, slots=True)
class JsonInputSnapshot:
    """One immutable-in-memory view of a regular, single-link JSON file."""

    label: str
    path: Path
    value: dict[str, Any]
    sha256: str
    byte_size: int
    device: int
    inode: int

    @property
    def identity(self) -> tuple[int, int]:
        return (self.device, self.inode)


def read_json_object(
    path: str | os.PathLike[str],
    *,
    label: str,
    maximum_bytes: int,
) -> JsonInputSnapshot:
    """Read a strict JSON object without following the final path component."""

    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
    ):
        raise ValueError("maximum_bytes must be a positive integer")
    candidate = Path(path).expanduser()
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise EvaluationContractError(
            "input_parent_missing",
            f"{label} parent directory is unavailable: {candidate.parent}",
        ) from exc
    resolved = parent / candidate.name
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(parent, directory_flags)
    except OSError as exc:
        raise EvaluationContractError(
            "input_parent_open_failed",
            f"{label} parent directory cannot be pinned: {parent}",
        ) from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(
            candidate.name,
            flags,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        os.close(parent_descriptor)
        raise EvaluationContractError(
            "input_open_failed",
            f"{label} cannot be opened safely: {resolved}",
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvaluationContractError(
                "input_not_regular",
                f"{label} must be a regular file: {resolved}",
            )
        if before.st_nlink != 1:
            raise EvaluationContractError(
                "input_hardlink_rejected",
                f"{label} must not have a hard-link alias: {resolved}",
            )
        if before.st_size <= 0:
            raise EvaluationContractError(
                "input_empty",
                f"{label} must not be empty: {resolved}",
            )
        if before.st_size > maximum_bytes:
            raise EvaluationContractError(
                "input_too_large",
                (
                    f"{label} exceeds its byte limit: "
                    f"observed={before.st_size}, maximum={maximum_bytes}"
                ),
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise EvaluationContractError(
                    "input_truncated",
                    f"{label} was truncated while being read: {resolved}",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvaluationContractError(
                "input_changed",
                f"{label} grew while being read: {resolved}",
            )
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise EvaluationContractError(
                "input_changed",
                f"{label} changed while being read: {resolved}",
            )
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluationContractError(
            "input_utf8_invalid",
            f"{label} must be UTF-8 JSON: {resolved}",
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=lambda pairs: _strict_object_pairs(
                pairs,
                label=label,
            ),
            parse_constant=lambda token: _reject_nonfinite(
                token,
                label=label,
            ),
        )
    except json.JSONDecodeError as exc:
        raise EvaluationContractError(
            "input_json_invalid",
            f"{label} is not valid JSON: {resolved}: {exc}",
        ) from exc
    if not isinstance(value, dict):
        raise EvaluationContractError(
            "input_not_object",
            f"{label} JSON root must be an object: {resolved}",
        )
    return JsonInputSnapshot(
        label=label,
        path=resolved,
        value=value,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
        device=before.st_dev,
        inode=before.st_ino,
    )


def require_distinct_inputs(
    snapshots: Iterable[JsonInputSnapshot],
) -> tuple[JsonInputSnapshot, ...]:
    """Reject duplicate paths and inode aliases across semantic inputs."""

    supplied = tuple(snapshots)
    identities: dict[tuple[int, int], JsonInputSnapshot] = {}
    paths: dict[Path, JsonInputSnapshot] = {}
    for snapshot in supplied:
        prior_identity = identities.get(snapshot.identity)
        prior_path = paths.get(snapshot.path)
        prior = prior_identity or prior_path
        if prior is not None:
            raise EvaluationContractError(
                "input_alias_rejected",
                (
                    f"{snapshot.label} aliases {prior.label}: "
                    f"{snapshot.path}"
                ),
            )
        identities[snapshot.identity] = snapshot
        paths[snapshot.path] = snapshot
    return supplied


def _strict_object_pairs(
    pairs: list[tuple[str, object]],
    *,
    label: str,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationContractError(
                "input_json_key_duplicate",
                f"{label} JSON contains a duplicate key: {key}",
            )
        result[key] = value
    return result


def _reject_nonfinite(token: str, *, label: str) -> object:
    raise EvaluationContractError(
        "input_json_nonfinite",
        f"{label} JSON contains a non-finite number: {token}",
    )
