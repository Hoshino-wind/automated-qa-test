"""审批收据的 Ed25519 detached signature 信任边界。"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import ApprovalReceipt, HumanControlContractError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - exercised by deployment packaging
    InvalidSignature = None
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


@dataclass(frozen=True, slots=True)
class ApprovalVerifier:
    """只保存 authority→key_id→公钥 allowlist，不接触私钥。"""

    _trusted_keys: Mapping[tuple[str, str], Any]

    @classmethod
    def configured(
        cls,
        *,
        trusted_authority_keys: (
            Mapping[str, Mapping[str, bytes | str]] | None
        ),
    ) -> ApprovalVerifier:
        if Ed25519PublicKey is None or serialization is None:
            if trusted_authority_keys:
                raise HumanControlContractError(
                    "ed25519_unavailable",
                    "缺少 cryptography Ed25519 支持，审批必须失败关闭",
                    path="$.trusted_authority_keys",
                )
            return cls(_trusted_keys={})

        keys: dict[tuple[str, str], Any] = {}
        for authority, key_ring in (trusted_authority_keys or {}).items():
            _canonical_name("authority", authority)
            if not isinstance(key_ring, Mapping) or not key_ring:
                raise HumanControlContractError(
                    "approval_key_ring_invalid",
                    "每个 authority 必须映射到非空 public key ring",
                    path=f"$.trusted_authority_keys.{authority}",
                )
            for key_id, encoded in key_ring.items():
                _canonical_name("key_id", key_id)
                keys[(authority, key_id)] = _load_public_key(
                    encoded,
                    path=(
                        "$.trusted_authority_keys."
                        f"{authority}.{key_id}"
                    ),
                )
        return cls(_trusted_keys=keys)

    @property
    def configured_for_verification(self) -> bool:
        return bool(self._trusted_keys)

    def verify(self, receipt: ApprovalReceipt) -> None:
        """按 `(authority,key_id)` 精确选择公钥并验 detached signature。"""

        if not isinstance(receipt, ApprovalReceipt):
            raise HumanControlContractError(
                "approval_receipt_invalid",
                "receipt 必须是 ApprovalReceipt",
                path="$.approval_receipt",
            )
        if not self.configured_for_verification:
            raise HumanControlContractError(
                "approval_trust_unconfigured",
                "审批写操作需要显式 authority public-key allowlist",
                path="$.approval_receipt",
            )
        public_key = self._trusted_keys.get(
            (receipt.authority, receipt.key_id),
        )
        if public_key is None:
            authority_known = any(
                authority == receipt.authority
                for authority, _ in self._trusted_keys
            )
            raise HumanControlContractError(
                (
                    "approval_key_unknown"
                    if authority_known
                    else "approval_authority_untrusted"
                ),
                (
                    "approval receipt key_id 未受信任"
                    if authority_known
                    else "approval receipt authority 不在 allowlist"
                ),
                path=(
                    "$.approval_receipt.key_id"
                    if authority_known
                    else "$.approval_receipt.authority"
                ),
            )
        signature = _decode_signature(receipt.signature)
        try:
            public_key.verify(
                signature,
                canonical_receipt_bytes(receipt),
            )
        except InvalidSignature as exc:
            raise HumanControlContractError(
                "approval_signature_invalid",
                "approval receipt Ed25519 signature 验证失败",
                path="$.approval_receipt.signature",
            ) from exc


def canonical_receipt_bytes(receipt: ApprovalReceipt) -> bytes:
    """返回 detached signature 覆盖的唯一 canonical unsigned payload。"""

    if not isinstance(receipt, ApprovalReceipt):
        raise HumanControlContractError(
            "approval_receipt_invalid",
            "receipt 必须是 ApprovalReceipt",
            path="$.approval_receipt",
        )
    return json.dumps(
        receipt.signing_payload(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def signed_receipt_dict(
    payload: Mapping[str, Any],
    *,
    private_key: Any,
) -> dict[str, Any]:
    """测试/外部审批适配器辅助；私钥必须由调用方显式提供。"""

    if Ed25519PrivateKey is None:
        raise HumanControlContractError(
            "ed25519_unavailable",
            "缺少 cryptography Ed25519 支持",
        )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise HumanControlContractError(
            "approval_private_key_invalid",
            "private_key 必须是 Ed25519PrivateKey",
            path="$.private_key",
        )
    unsigned = {
        **dict(payload),
        "algorithm": "Ed25519",
        "signature": _encode_signature(b"\x00" * 64),
    }
    receipt = ApprovalReceipt.from_dict(unsigned)
    signature = private_key.sign(canonical_receipt_bytes(receipt))
    return {
        **receipt.signing_payload(),
        "signature": _encode_signature(signature),
    }


def public_key_pem(private_key: Any) -> str:
    """仅供测试/部署准备公开 PEM；绝不序列化私钥。"""

    if (
        Ed25519PrivateKey is None
        or serialization is None
        or not isinstance(private_key, Ed25519PrivateKey)
    ):
        raise HumanControlContractError(
            "approval_private_key_invalid",
            "private_key 必须是 Ed25519PrivateKey",
            path="$.private_key",
        )
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _load_public_key(value: bytes | str, *, path: str) -> Any:
    if serialization is None or Ed25519PublicKey is None:
        raise HumanControlContractError(
            "ed25519_unavailable",
            "缺少 cryptography Ed25519 支持",
            path=path,
        )
    encoded = value.encode("ascii") if isinstance(value, str) else value
    if not isinstance(encoded, bytes):
        raise HumanControlContractError(
            "approval_public_key_invalid",
            "public key 必须是 PEM bytes/string",
            path=path,
        )
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise HumanControlContractError(
            "approval_public_key_invalid",
            "public key 不是合法 PEM",
            path=path,
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise HumanControlContractError(
            "approval_public_key_algorithm_invalid",
            "public key 必须是 Ed25519",
            path=path,
        )
    return key


def _encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise HumanControlContractError(
            "approval_signature_invalid",
            "signature 必须是非空 base64url",
            path="$.approval_receipt.signature",
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise HumanControlContractError(
            "approval_signature_invalid",
            "signature 不是合法 base64url",
            path="$.approval_receipt.signature",
        ) from exc
    if len(decoded) != 64 or _encode_signature(decoded) != value:
        raise HumanControlContractError(
            "approval_signature_invalid",
            "signature 必须是 canonical Ed25519 base64url",
            path="$.approval_receipt.signature",
        )
    return decoded


def _canonical_name(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
    ):
        raise HumanControlContractError(
            f"approval_{name}_invalid",
            f"{name} 必须是非空规范字符串",
            path=f"$.{name}",
        )
    return value
