"""Externally signed anti-rollback checkpoints for human-control journals."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - deployment packaging boundary
    InvalidSignature = None
    serialization = None
    Ed25519PublicKey = None

from ._journal import GENESIS_HASH, HumanControlJournalError
from .contracts import canonical_sha256, canonical_timestamp, parse_timestamp

JOURNAL_CHECKPOINT_SCHEMA_VERSION = 1
MAX_CHECKPOINT_BYTES = 64 * 1024
LOCAL_TEST_MODE = "local-test"
PRODUCTION_MODE = "production"

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_JOURNAL_KIND_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_SIGNING_FIELDS = {
    "schema_version",
    "journal_kind",
    "journal_path_sha256",
    "event_count",
    "terminal_event_hash",
    "issued_at",
    "expires_at",
    "authority",
    "key_id",
    "algorithm",
}


@dataclass(frozen=True, slots=True)
class JournalCheckpoint:
    """An authority-signed statement about one immutable journal prefix."""

    journal_kind: str
    journal_path_sha256: str
    event_count: int
    terminal_event_hash: str
    issued_at: str
    expires_at: str
    authority: str
    key_id: str
    algorithm: str
    signature: str
    schema_version: int = JOURNAL_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != JOURNAL_CHECKPOINT_SCHEMA_VERSION:
            raise HumanControlJournalError(
                "checkpoint_schema_unsupported",
                (
                    "checkpoint schema_version 必须等于 "
                    f"{JOURNAL_CHECKPOINT_SCHEMA_VERSION}"
                ),
            )
        if (
            not isinstance(self.journal_kind, str)
            or _JOURNAL_KIND_PATTERN.fullmatch(self.journal_kind) is None
        ):
            raise HumanControlJournalError(
                "checkpoint_journal_kind_invalid",
                "checkpoint journal_kind 不是合法标识符",
            )
        _sha256(
            "journal_path_sha256",
            self.journal_path_sha256,
        )
        if (
            isinstance(self.event_count, bool)
            or not isinstance(self.event_count, int)
            or self.event_count < 0
        ):
            raise HumanControlJournalError(
                "checkpoint_event_count_invalid",
                "checkpoint event_count 必须是非负整数",
            )
        _sha256(
            "terminal_event_hash",
            self.terminal_event_hash,
        )
        if (
            self.event_count == 0
            and self.terminal_event_hash != GENESIS_HASH
        ):
            raise HumanControlJournalError(
                "checkpoint_genesis_invalid",
                "空 journal checkpoint 必须绑定 genesis hash",
            )
        issued_at = canonical_timestamp(
            self.issued_at,
            path="$.issued_at",
        )
        expires_at = canonical_timestamp(
            self.expires_at,
            path="$.expires_at",
        )
        if parse_timestamp(expires_at) <= parse_timestamp(issued_at):
            raise HumanControlJournalError(
                "checkpoint_expiry_invalid",
                "checkpoint expires_at 必须晚于 issued_at",
            )
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        _identifier("authority", self.authority)
        _identifier("key_id", self.key_id)
        if self.algorithm != "Ed25519":
            raise HumanControlJournalError(
                "checkpoint_algorithm_invalid",
                "checkpoint algorithm 必须是 Ed25519",
            )
        if not isinstance(self.signature, str) or not self.signature:
            raise HumanControlJournalError(
                "checkpoint_signature_invalid",
                "checkpoint signature 必须是非空 canonical base64url",
            )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        payload = _strict_object(value)
        expected = {*_SIGNING_FIELDS, "signature"}
        unknown = sorted(set(payload) - expected)
        missing = sorted(expected - set(payload))
        if unknown:
            raise HumanControlJournalError(
                "checkpoint_fields_unknown",
                f"checkpoint 包含未知字段：{', '.join(unknown)}",
            )
        if missing:
            raise HumanControlJournalError(
                "checkpoint_fields_missing",
                f"checkpoint 缺少字段：{', '.join(missing)}",
            )
        return cls(
            schema_version=payload["schema_version"],
            journal_kind=payload["journal_kind"],
            journal_path_sha256=payload["journal_path_sha256"],
            event_count=payload["event_count"],
            terminal_event_hash=payload["terminal_event_hash"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            authority=payload["authority"],
            key_id=payload["key_id"],
            algorithm=payload["algorithm"],
            signature=payload["signature"],
        )

    def signing_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "journal_kind": self.journal_kind,
            "journal_path_sha256": self.journal_path_sha256,
            "event_count": self.event_count,
            "terminal_event_hash": self.terminal_event_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authority": self.authority,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signing_payload(),
            "signature": self.signature,
        }


class JournalCheckpointVerifier:
    """Verify a signed exact-tail anchor without loading a private key."""

    def __init__(
        self,
        *,
        mode: str,
        checkpoint_path: Path | None,
        trusted_authority_keys: Mapping[tuple[str, str], Any],
        clock: Callable[[], datetime],
    ) -> None:
        if mode not in {LOCAL_TEST_MODE, PRODUCTION_MODE}:
            raise HumanControlJournalError(
                "journal_mode_invalid",
                "journal mode 必须是 local-test 或 production",
            )
        if mode == PRODUCTION_MODE:
            if checkpoint_path is None:
                raise HumanControlJournalError(
                    "checkpoint_required",
                    "production journal 必须显式提供外部 checkpoint",
                )
            if not trusted_authority_keys:
                raise HumanControlJournalError(
                    "checkpoint_trust_unconfigured",
                    "production journal 必须配置 checkpoint 公钥 allowlist",
                )
        elif checkpoint_path is not None:
            raise HumanControlJournalError(
                "checkpoint_mode_mismatch",
                "local-test mode 不得伪装使用 production checkpoint",
            )
        self.mode = mode
        self.checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else None
        )
        self._trusted_keys = dict(trusted_authority_keys)
        self._clock = clock
        self._assurance: dict[str, Any] = {
            "mode": self.mode,
            "checkpoint_required": self.mode == PRODUCTION_MODE,
            "production_ready": False,
            "covered_count": None,
            "current_count": None,
            "tail_count": None,
        }

    @classmethod
    def configured(
        cls,
        *,
        mode: str = LOCAL_TEST_MODE,
        checkpoint_path: Path | None = None,
        trusted_authority_keys: (
            Mapping[str, Mapping[str, bytes | str]] | None
        ) = None,
        clock: Callable[[], datetime] | None = None,
    ) -> Self:
        if Ed25519PublicKey is None or serialization is None:
            if mode == PRODUCTION_MODE or trusted_authority_keys:
                raise HumanControlJournalError(
                    "checkpoint_ed25519_unavailable",
                    "缺少 cryptography Ed25519 支持，checkpoint 必须失败关闭",
                )
            return cls(
                mode=mode,
                checkpoint_path=checkpoint_path,
                trusted_authority_keys={},
                clock=clock or (lambda: datetime.now(UTC)),
            )
        keys: dict[tuple[str, str], Any] = {}
        for authority, key_ring in (trusted_authority_keys or {}).items():
            _identifier("authority", authority)
            if not isinstance(key_ring, Mapping) or not key_ring:
                raise HumanControlJournalError(
                    "checkpoint_key_ring_invalid",
                    "每个 checkpoint authority 必须有非空 public key ring",
                )
            for key_id, value in key_ring.items():
                _identifier("key_id", key_id)
                keys[(authority, key_id)] = _load_public_key(value)
        return cls(
            mode=mode,
            checkpoint_path=checkpoint_path,
            trusted_authority_keys=keys,
            clock=clock or (lambda: datetime.now(UTC)),
        )

    @property
    def assurance(self) -> dict[str, Any]:
        return dict(self._assurance)

    def note_append(self, *, current_count: int) -> None:
        """Record that a durable append is not externally anchored yet."""

        if self.mode != PRODUCTION_MODE:
            self._assurance.update(
                {
                    "production_ready": False,
                    "covered_count": None,
                    "current_count": current_count,
                    "tail_count": None,
                },
            )
            return
        covered_count = self._assurance.get("covered_count")
        if not isinstance(covered_count, int):
            covered_count = max(0, current_count - 1)
        self._set_assurance(
            covered_count=covered_count,
            current_count=current_count,
        )

    def verify(
        self,
        *,
        journal_kind: str,
        events_path: Path,
        projection_path: Path,
        events: Sequence[Any],
    ) -> JournalCheckpoint | None:
        """Require the signed checkpoint to cover the exact current journal."""

        if self.mode == LOCAL_TEST_MODE:
            self._assurance.update(
                {
                    "production_ready": False,
                    "covered_count": None,
                    "current_count": len(events),
                    "tail_count": None,
                },
            )
            return None
        if self.checkpoint_path is None:  # defensive; constructor rejects it
            raise HumanControlJournalError(
                "checkpoint_required",
                "production journal 缺少 checkpoint",
            )
        checkpoint = _read_checkpoint(
            self.checkpoint_path,
            forbidden_paths=(events_path, projection_path),
        )
        expected_identity = canonical_journal_path_sha256(events_path)
        if checkpoint.journal_kind != journal_kind:
            raise HumanControlJournalError(
                "checkpoint_journal_kind_mismatch",
                "checkpoint 绑定了不同 journal kind",
            )
        if checkpoint.journal_path_sha256 != expected_identity:
            raise HumanControlJournalError(
                "checkpoint_journal_identity_mismatch",
                "checkpoint 绑定了不同 canonical journal path",
            )
        public_key = self._trusted_keys.get(
            (checkpoint.authority, checkpoint.key_id),
        )
        if public_key is None:
            authority_known = any(
                authority == checkpoint.authority
                for authority, _ in self._trusted_keys
            )
            raise HumanControlJournalError(
                (
                    "checkpoint_key_unknown"
                    if authority_known
                    else "checkpoint_authority_untrusted"
                ),
                (
                    "checkpoint key_id 未受信任"
                    if authority_known
                    else "checkpoint authority 不在 allowlist"
                ),
            )
        try:
            public_key.verify(
                _decode_signature(checkpoint.signature),
                canonical_checkpoint_bytes(checkpoint),
            )
        except InvalidSignature as exc:
            raise HumanControlJournalError(
                "checkpoint_signature_invalid",
                "checkpoint Ed25519 signature 验证失败",
            ) from exc

        now = self._trusted_now()
        if parse_timestamp(checkpoint.issued_at) > now:
            raise HumanControlJournalError(
                "checkpoint_issued_in_future",
                "checkpoint issued_at 晚于可信当前时间",
            )
        if now >= parse_timestamp(checkpoint.expires_at):
            raise HumanControlJournalError(
                "checkpoint_expired",
                "checkpoint 已超过 expires_at",
            )
        current_count = len(events)
        covered_count = checkpoint.event_count
        self._set_assurance(
            covered_count=covered_count,
            current_count=current_count,
        )
        if current_count < covered_count:
            raise HumanControlJournalError(
                "checkpoint_journal_rollback",
                (
                    "journal event count 短于受信 checkpoint："
                    f"{current_count} < {covered_count}"
                ),
                covered_count=covered_count,
                current_count=current_count,
                tail_count=0,
            )
        prefix_hash = (
            GENESIS_HASH
            if checkpoint.event_count == 0
            else events[checkpoint.event_count - 1].event_hash
        )
        if prefix_hash != checkpoint.terminal_event_hash:
            raise HumanControlJournalError(
                "checkpoint_prefix_mismatch",
                "journal 在受信 checkpoint 位置不是同一不可变前缀",
                covered_count=covered_count,
                current_count=current_count,
                tail_count=max(0, current_count - covered_count),
            )
        if current_count > covered_count:
            raise HumanControlJournalError(
                "checkpoint_tail_uncovered",
                (
                    "production journal 存在 checkpoint 未覆盖的 tail："
                    f"{current_count} current, {covered_count} covered"
                ),
                covered_count=covered_count,
                current_count=current_count,
                tail_count=current_count - covered_count,
            )
        self._set_assurance(
            covered_count=covered_count,
            current_count=current_count,
            production_ready=True,
        )
        return checkpoint

    def _set_assurance(
        self,
        *,
        covered_count: int,
        current_count: int,
        production_ready: bool = False,
    ) -> None:
        self._assurance.update(
            {
                "production_ready": production_ready,
                "covered_count": covered_count,
                "current_count": current_count,
                "tail_count": max(0, current_count - covered_count),
            },
        )

    def _trusted_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise HumanControlJournalError(
                "checkpoint_clock_invalid",
                "checkpoint clock 必须返回 timezone-aware datetime",
            )
        return value.astimezone(UTC)


def canonical_journal_path_sha256(events_path: Path) -> str:
    """Content-address the real, absolute journal path without exposing it."""

    raw = Path(events_path)
    canonical = _canonical_path(raw)
    return canonical_sha256(
        {
            "domain": "qa-human-control-journal-path-v1",
            "canonical_path": os.path.normcase(os.fspath(canonical)),
        },
    )


def checkpoint_signing_payload(
    *,
    journal_kind: str,
    events_path: Path,
    event_count: int,
    terminal_event_hash: str,
    issued_at: str,
    expires_at: str,
    authority: str,
    key_id: str,
) -> dict[str, Any]:
    """Build an unsigned payload for an independent checkpoint authority."""

    checkpoint = JournalCheckpoint(
        journal_kind=journal_kind,
        journal_path_sha256=canonical_journal_path_sha256(events_path),
        event_count=event_count,
        terminal_event_hash=terminal_event_hash,
        issued_at=issued_at,
        expires_at=expires_at,
        authority=authority,
        key_id=key_id,
        algorithm="Ed25519",
        signature="unsigned-placeholder",
    )
    return checkpoint.signing_payload()


def canonical_checkpoint_bytes(
    value: JournalCheckpoint | Mapping[str, Any],
) -> bytes:
    """Canonical bytes signed by the external checkpoint authority."""

    if isinstance(value, JournalCheckpoint):
        payload = value.signing_payload()
    else:
        payload = _strict_object(value)
        unknown = sorted(set(payload) - _SIGNING_FIELDS)
        missing = sorted(_SIGNING_FIELDS - set(payload))
        if unknown:
            raise HumanControlJournalError(
                "checkpoint_fields_unknown",
                f"checkpoint signing payload 包含未知字段：{', '.join(unknown)}",
            )
        if missing:
            raise HumanControlJournalError(
                "checkpoint_fields_missing",
                f"checkpoint signing payload 缺少字段：{', '.join(missing)}",
            )
        payload = JournalCheckpoint(
            **payload,
            signature="unsigned-placeholder",
        ).signing_payload()
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_checkpoint(
    path: Path,
    *,
    forbidden_paths: Sequence[Path],
) -> JournalCheckpoint:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HumanControlJournalError(
            "checkpoint_unreadable",
            str(exc),
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise HumanControlJournalError(
            "checkpoint_not_file",
            f"checkpoint 不是普通文件：{path}",
        )
    if metadata.st_nlink != 1:
        raise HumanControlJournalError(
            "checkpoint_hardlink_unsafe",
            "checkpoint hard-link count 必须等于 1",
        )
    if metadata.st_size <= 0 or metadata.st_size > MAX_CHECKPOINT_BYTES:
        raise HumanControlJournalError(
            "checkpoint_size_invalid",
            (
                "checkpoint 大小必须在 1.."
                f"{MAX_CHECKPOINT_BYTES} bytes"
            ),
        )
    checkpoint_identity = (metadata.st_dev, metadata.st_ino)
    checkpoint_canonical = _canonical_path(path)
    for forbidden in forbidden_paths:
        forbidden_canonical = _canonical_path(forbidden)
        if checkpoint_canonical == forbidden_canonical:
            raise HumanControlJournalError(
                "checkpoint_alias_unsafe",
                "checkpoint 不得与 journal/projection 使用同一路径",
            )
        try:
            forbidden_metadata = forbidden.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise HumanControlJournalError(
                "checkpoint_alias_unverifiable",
                str(exc),
            ) from exc
        if (
            forbidden_metadata.st_dev,
            forbidden_metadata.st_ino,
        ) == checkpoint_identity:
            raise HumanControlJournalError(
                "checkpoint_alias_unsafe",
                "checkpoint 不得与 journal/projection 指向同一文件",
            )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HumanControlJournalError(
            "checkpoint_unreadable",
            str(exc),
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != checkpoint_identity
        ):
            raise HumanControlJournalError(
                "checkpoint_path_replaced",
                "checkpoint path 在读取前被替换或建立了别名",
            )
        chunks: list[bytes] = []
        remaining = MAX_CHECKPOINT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise HumanControlJournalError(
                "checkpoint_size_invalid",
                f"checkpoint 超过 {MAX_CHECKPOINT_BYTES} bytes",
            )
        final_opened = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as exc:
            raise HumanControlJournalError(
                "checkpoint_path_replaced",
                "checkpoint path 在读取期间消失",
            ) from exc
        if (
            (final_opened.st_dev, final_opened.st_ino)
            != checkpoint_identity
            or (current.st_dev, current.st_ino)
            != checkpoint_identity
            or final_opened.st_size != len(raw)
        ):
            raise HumanControlJournalError(
                "checkpoint_path_replaced",
                "checkpoint path 或内容在读取期间发生变化",
            )
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HumanControlJournalError(
            "checkpoint_json_invalid",
            "checkpoint 必须是 UTF-8 JSON",
        ) from exc
    return JournalCheckpoint.from_dict(_strict_json_object(text))


def _strict_json_object(raw: str) -> dict[str, Any]:
    def object_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HumanControlJournalError(
                    "checkpoint_json_duplicate_key",
                    f"checkpoint JSON 包含重复 key：{key}",
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise HumanControlJournalError(
            "checkpoint_json_nonfinite",
            f"checkpoint JSON 不允许非有限数：{value}",
        )

    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        message = (
            exc.msg
            if isinstance(exc, json.JSONDecodeError)
            else "JSON nesting 过深"
        )
        raise HumanControlJournalError(
            "checkpoint_json_invalid",
            f"checkpoint JSON 非法：{message}",
        ) from exc
    if not isinstance(value, dict):
        raise HumanControlJournalError(
            "checkpoint_json_not_object",
            "checkpoint JSON 根必须是 object",
        )
    return value


def _strict_object(value: Any) -> dict[str, Any]:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise HumanControlJournalError(
            "checkpoint_json_invalid",
            "checkpoint 必须能无损表示为标准 JSON object",
        ) from exc
    if not isinstance(decoded, dict):
        raise HumanControlJournalError(
            "checkpoint_json_not_object",
            "checkpoint 必须是 JSON object",
        )
    return decoded


def _load_public_key(value: bytes | str) -> Any:
    if serialization is None or Ed25519PublicKey is None:
        raise HumanControlJournalError(
            "checkpoint_ed25519_unavailable",
            "缺少 cryptography Ed25519 支持",
        )
    encoded = value.encode("ascii") if isinstance(value, str) else value
    if not isinstance(encoded, bytes):
        raise HumanControlJournalError(
            "checkpoint_public_key_invalid",
            "checkpoint public key 必须是 PEM bytes/string",
        )
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise HumanControlJournalError(
            "checkpoint_public_key_invalid",
            "checkpoint public key 不是合法 PEM",
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise HumanControlJournalError(
            "checkpoint_public_key_algorithm_invalid",
            "checkpoint public key 必须是 Ed25519",
        )
    return key


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise HumanControlJournalError(
            "checkpoint_signature_invalid",
            "checkpoint signature 不是合法 base64url",
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != 64 or canonical != value:
        raise HumanControlJournalError(
            "checkpoint_signature_invalid",
            "checkpoint signature 必须是 canonical Ed25519 base64url",
        )
    return decoded


def _identifier(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise HumanControlJournalError(
            f"checkpoint_{name}_invalid",
            f"checkpoint {name} 不是合法标识符",
        )
    return value


def _sha256(name: str, value: Any) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise HumanControlJournalError(
            f"checkpoint_{name}_invalid",
            f"checkpoint {name} 必须是 64 位小写 SHA-256",
        )
    return value


def _canonical_path(path: Path) -> Path:
    try:
        return Path(
            os.path.abspath(os.fspath(path)),
        ).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HumanControlJournalError(
            "checkpoint_path_invalid",
            f"无法规范化 checkpoint/journal path：{path}",
        ) from exc
