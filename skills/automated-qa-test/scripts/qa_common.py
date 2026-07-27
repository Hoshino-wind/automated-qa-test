#!/usr/bin/env python3
"""QA 辅助脚本共享的安全文件与契约工具。"""

import errno
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA_VERSION = 2
_READ_CHUNK_BYTES = 1024 * 1024
_STABLE_METADATA_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


class StableFileReadError(ValueError):
    """A file cannot be consumed as one stable, ordinary input."""

    def __init__(self, code: str, message: str, *, path: Path) -> None:
        self.code = code
        self.path = path
        super().__init__(message)


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """通过固定父目录描述符原子替换普通单链接文件。

    最终组件若是 symlink、目录、特殊文件或硬链接会默认拒绝，避免调用方
    在校验与写入之间把输出重定向到工作区外的权威文件。
    """

    expanded = path.expanduser()
    expanded.parent.mkdir(parents=True, exist_ok=True)
    parent = expanded.parent.resolve(strict=True)
    target = parent / expanded.name
    if target.name in {"", ".", ".."}:
        raise ValueError("output path must name a file")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(parent, directory_flags)
    temporary_name: str | None = None
    try:
        _reject_unsafe_existing_output(
            target.name,
            directory_descriptor=parent_descriptor,
        )
        descriptor, temporary_path_text = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_path_text)
        temporary_name = temporary_path.name
        with os.fdopen(descriptor, "w", encoding=encoding) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _reject_unsafe_existing_output(
            target.name,
            directory_descriptor=parent_descriptor,
        )
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
    except Exception:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_descriptor)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False))


def read_stable_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Read a bounded regular single-link file through pinned descriptors."""

    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
    ):
        raise ValueError("max_bytes must be a positive integer")
    parent_descriptor, descriptor, resolved, before = (
        _open_pinned_regular_file(path)
    )
    try:
        if before.st_size > max_bytes:
            raise StableFileReadError(
                "too_large",
                f"file exceeds {max_bytes} bytes: {resolved}",
                path=resolved,
            )
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, remaining),
            )
            if not chunk:
                raise StableFileReadError(
                    "changed",
                    f"file was truncated while being read: {resolved}",
                    path=resolved,
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise StableFileReadError(
                "changed",
                f"file grew while being read: {resolved}",
                path=resolved,
            )
        _require_stable_metadata(
            descriptor,
            before=before,
            path=resolved,
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def file_sha256(path: Path | None) -> str | None:
    """Hash one stable regular single-link file without following symlinks.

    Missing, unsafe, unreadable, or read-unstable inputs return ``None`` rather
    than producing an ambiguous digest.
    """

    if path is None:
        return None
    try:
        parent_descriptor, descriptor, resolved, before = (
            _open_pinned_regular_file(path)
        )
    except (FileNotFoundError, StableFileReadError):
        return None
    except OSError:
        return None
    digest = hashlib.sha256()
    observed_size = 0
    try:
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        if observed_size != before.st_size:
            raise StableFileReadError(
                "changed",
                f"file size changed while being hashed: {resolved}",
                path=resolved,
            )
        _require_stable_metadata(
            descriptor,
            before=before,
            path=resolved,
        )
        return digest.hexdigest()
    except (OSError, StableFileReadError):
        return None
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def _open_pinned_regular_file(
    path: Path,
) -> tuple[int, int, Path, os.stat_result]:
    """Open the final component relative to a pinned resolved parent."""

    candidate = path.expanduser()
    if candidate.name in {"", ".", ".."}:
        raise StableFileReadError(
            "not_regular_file",
            f"path must name a regular file: {candidate}",
            path=candidate,
        )
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(parent, directory_flags)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        os.close(parent_descriptor)
        raise StableFileReadError(
            "safe_open_unsupported",
            "platform cannot safely reject symbolic-link inputs",
            path=resolved,
        )
    try:
        entry_metadata = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_regular_single_link(entry_metadata, path=resolved)
    except Exception:
        os.close(parent_descriptor)
        raise
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= nofollow
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(
            candidate.name,
            flags,
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        os.close(parent_descriptor)
        if error.errno == errno.ELOOP:
            raise StableFileReadError(
                "symlink_rejected",
                f"symbolic-link input is rejected: {resolved}",
                path=resolved,
            ) from error
        raise
    try:
        metadata = os.fstat(descriptor)
        _require_regular_single_link(metadata, path=resolved)
        if any(
            getattr(entry_metadata, field) != getattr(metadata, field)
            for field in _STABLE_METADATA_FIELDS
        ):
            raise StableFileReadError(
                "changed",
                f"file changed while being opened: {resolved}",
                path=resolved,
            )
    except Exception:
        os.close(descriptor)
        os.close(parent_descriptor)
        raise
    return parent_descriptor, descriptor, resolved, metadata


def _require_regular_single_link(
    metadata: os.stat_result,
    *,
    path: Path,
) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise StableFileReadError(
            "symlink_rejected",
            f"symbolic-link input is rejected: {path}",
            path=path,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise StableFileReadError(
            "not_regular_file",
            f"input is not a regular file: {path}",
            path=path,
        )
    if metadata.st_nlink != 1:
        raise StableFileReadError(
            "hardlink_rejected",
            f"hard-linked input is rejected: {path}",
            path=path,
        )


def _require_stable_metadata(
    descriptor: int,
    *,
    before: os.stat_result,
    path: Path,
) -> None:
    after = os.fstat(descriptor)
    if any(
        getattr(before, field) != getattr(after, field)
        for field in _STABLE_METADATA_FIELDS
    ):
        raise StableFileReadError(
            "changed",
            f"file changed while being read: {path}",
            path=path,
        )


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def safe_output_path(
    output: Path,
    *,
    protected_paths: list[Path] | tuple[Path, ...] = (),
    protected_roots: list[Path] | tuple[Path, ...] = (),
) -> Path:
    """拒绝输出覆盖输入、硬链接别名或权威存储目录。"""

    expanded_output = output.expanduser()
    resolved_output = (
        expanded_output.parent.resolve(strict=False)
        / expanded_output.name
    )
    if resolved_output.name in {"", ".", ".."}:
        raise ValueError("output path must name a file")
    if resolved_output.exists() or resolved_output.is_symlink():
        observed = resolved_output.lstat()
        if stat.S_ISLNK(observed.st_mode):
            raise ValueError(
                f"output path must not be a symlink: {resolved_output}"
            )
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError(
                f"output path must be a regular file: {resolved_output}"
            )
        if observed.st_nlink != 1:
            raise ValueError(
                f"output path must not be a hard link: {resolved_output}"
            )
    for protected in protected_paths:
        resolved_protected = protected.expanduser().resolve()
        aliases = resolved_output == resolved_protected
        if (
            not aliases
            and resolved_output.exists()
            and resolved_protected.exists()
        ):
            try:
                aliases = resolved_output.samefile(resolved_protected)
            except OSError:
                aliases = False
        if aliases:
            raise ValueError(
                f"output path aliases protected input: {resolved_protected}"
            )
    for root in protected_roots:
        resolved_root = root.expanduser().resolve()
        if (
            resolved_output == resolved_root
            or resolved_root in resolved_output.parents
        ):
            raise ValueError(
                f"output path is inside protected store: {resolved_root}"
            )
    return resolved_output


def _reject_unsafe_existing_output(
    name: str,
    *,
    directory_descriptor: int,
) -> None:
    """使用父目录描述符检查最终组件，不跟随 symlink。"""

    try:
        observed = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if stat.S_ISLNK(observed.st_mode):
        raise ValueError(f"output path must not be a symlink: {name}")
    if not stat.S_ISREG(observed.st_mode):
        raise ValueError(f"output path must be a regular file: {name}")
    if observed.st_nlink != 1:
        raise ValueError(f"output path must not be a hard link: {name}")


def schema_version_error(value: Any, *, field: str, artifact: str) -> str | None:
    if value != SUPPORTED_SCHEMA_VERSION:
        return f"{artifact}.{field} must equal supported major version {SUPPORTED_SCHEMA_VERSION}; got {value!r}."
    return None


def manual_evidence_manifest_errors(manifest: dict[str, Any] | None, required_evidence_ids: set[str]) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manual evidence manifest must be a JSON object"]
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("manual evidence manifest schema_version must equal 1")
    if manifest.get("mode") != "manual":
        errors.append("manual evidence manifest mode must equal 'manual'")
    for field in ("operator", "observed_at", "statement"):
        if not isinstance(manifest.get(field), str) or not str(manifest.get(field)).strip():
            errors.append(f"manual evidence manifest {field} must be non-empty text")
    declared = {
        str(item).strip()
        for item in manifest.get("evidence_ids", [])
        if isinstance(item, str) and item.strip()
    } if isinstance(manifest.get("evidence_ids"), list) else set()
    missing = sorted(required_evidence_ids - declared)
    if missing:
        errors.append(f"manual evidence manifest is missing passed evidence ids: {', '.join(missing)}")
    return errors
