"""用确定性门禁和 HMAC 签发不可伪造的执行授权。"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Self

from qa_core.runtime import BudgetExceeded, RunBudget
from qa_core.tools import (
    RiskClass,
    ToolContractError,
    ToolInvocation,
    ToolRegistry,
    ToolSpec,
)

from .contracts import AgentContractError, PlanProposal, ProbeProposal

Clock = Callable[[], float]
AUTHORIZATION_SCHEMA_VERSION = 1
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_RISK_ORDER = {
    RiskClass.LOW: 0,
    RiskClass.MEDIUM: 1,
    RiskClass.HIGH: 2,
    RiskClass.CRITICAL: 3,
}
_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "authorization_id",
        "policy_version",
        "issued_at",
        "expires_at",
        "action",
        "tool_version",
        "executor_version",
        "risk_class",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "tool_spec_sha256",
        "plan_sha256",
        "probe_sha256",
        "invocation_sha256",
        "budget_sha256",
        "timeout_seconds",
        "output_limit_bytes",
        "required_authorizations",
        "signature",
    },
)


class PolicyContractError(ValueError):
    """策略配置或授权载荷不满足安全约束。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
    ) -> None:
        self.code = code
        self.path = path
        super().__init__(message)

    def to_dict(self) -> dict[str, str | int]:
        """返回稳定的结构化错误。"""

        return {
            "schema_version": 1,
            "error": "policy_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    """策略签发、执行器可独立验证的一次性授权声明。"""

    authorization_id: str
    policy_version: str
    issued_at: float
    expires_at: float
    action: str
    tool_version: str
    executor_version: str
    risk_class: RiskClass | str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    tool_spec_sha256: str
    plan_sha256: str
    probe_sha256: str
    invocation_sha256: str
    budget_sha256: str
    timeout_seconds: float
    output_limit_bytes: int
    required_authorizations: tuple[str, ...]
    signature: str
    schema_version: int = AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORIZATION_SCHEMA_VERSION:
            raise PolicyContractError(
                "authorization_schema_unsupported",
                (
                    "authorization schema_version 必须等于 "
                    f"{AUTHORIZATION_SCHEMA_VERSION}"
                ),
                path="$.schema_version",
            )
        object.__setattr__(
            self,
            "authorization_id",
            _sha256("authorization_id", self.authorization_id),
        )
        object.__setattr__(
            self,
            "policy_version",
            _text("policy_version", self.policy_version),
        )
        issued_at = _finite_number("issued_at", self.issued_at)
        expires_at = _finite_number("expires_at", self.expires_at)
        if expires_at <= issued_at:
            raise PolicyContractError(
                "authorization_window_invalid",
                "expires_at 必须晚于 issued_at",
                path="$.expires_at",
            )
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        for field_name in (
            "action",
            "tool_version",
            "executor_version",
        ):
            object.__setattr__(
                self,
                field_name,
                _text(field_name, getattr(self, field_name)),
            )
        try:
            risk_class = RiskClass(self.risk_class)
        except (TypeError, ValueError) as exc:
            raise PolicyContractError(
                "risk_class_invalid",
                "risk_class 不是受支持的风险等级",
                path="$.risk_class",
            ) from exc
        object.__setattr__(self, "risk_class", risk_class)
        for field_name in (
            "context_sha256",
            "state_sha256",
            "tool_registry_sha256",
            "tool_spec_sha256",
            "plan_sha256",
            "probe_sha256",
            "invocation_sha256",
            "budget_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "timeout_seconds",
            _positive_number(
                "timeout_seconds",
                self.timeout_seconds,
            ),
        )
        object.__setattr__(
            self,
            "output_limit_bytes",
            _positive_integer(
                "output_limit_bytes",
                self.output_limit_bytes,
            ),
        )
        object.__setattr__(
            self,
            "required_authorizations",
            _string_set(
                "required_authorizations",
                self.required_authorizations,
            ),
        )
        object.__setattr__(
            self,
            "signature",
            _sha256("signature", self.signature),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        """严格解析授权；解析成功不代表签名已经验证。"""

        if not isinstance(value, Mapping):
            raise PolicyContractError(
                "authorization_not_object",
                "authorization 必须是 object",
            )
        fields = set(value)
        unknown = sorted(fields - _AUTHORIZATION_FIELDS)
        if unknown:
            raise PolicyContractError(
                "authorization_fields_unknown",
                f"authorization 包含未知字段：{', '.join(unknown)}",
            )
        missing = sorted(_AUTHORIZATION_FIELDS - fields)
        if missing:
            raise PolicyContractError(
                "authorization_fields_missing",
                f"authorization 缺少字段：{', '.join(missing)}",
            )
        required_authorizations = value["required_authorizations"]
        if not isinstance(required_authorizations, list):
            raise PolicyContractError(
                "authorization_list_invalid",
                "required_authorizations 必须是 JSON array",
                path="$.required_authorizations",
            )
        return cls(
            schema_version=value["schema_version"],
            authorization_id=value["authorization_id"],
            policy_version=value["policy_version"],
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
            action=value["action"],
            tool_version=value["tool_version"],
            executor_version=value["executor_version"],
            risk_class=value["risk_class"],
            context_sha256=value["context_sha256"],
            state_sha256=value["state_sha256"],
            tool_registry_sha256=value[
                "tool_registry_sha256"
            ],
            tool_spec_sha256=value["tool_spec_sha256"],
            plan_sha256=value["plan_sha256"],
            probe_sha256=value["probe_sha256"],
            invocation_sha256=value["invocation_sha256"],
            budget_sha256=value["budget_sha256"],
            timeout_seconds=value["timeout_seconds"],
            output_limit_bytes=value["output_limit_bytes"],
            required_authorizations=tuple(
                required_authorizations,
            ),
            signature=value["signature"],
        )

    def verify(
        self,
        *,
        hmac_key: bytes,
        invocation: ToolInvocation,
        context_sha256: str,
        state_sha256: str,
        tool_registry_sha256: str,
        plan_sha256: str,
        probe_sha256: str,
        policy_version: str,
        now: float,
        executor_version: str | None = None,
    ) -> bool:
        """独立验证签名、时效和全部输入绑定。"""

        try:
            key = _hmac_key(hmac_key)
            current_time = _finite_number("now", now)
            if current_time < self.issued_at:
                return False
            if current_time >= self.expires_at:
                return False
            if not isinstance(invocation, ToolInvocation):
                return False
            expected = {
                "policy_version": _text(
                    "policy_version",
                    policy_version,
                ),
                "context_sha256": _sha256(
                    "context_sha256",
                    context_sha256,
                ),
                "state_sha256": _sha256(
                    "state_sha256",
                    state_sha256,
                ),
                "tool_registry_sha256": _sha256(
                    "tool_registry_sha256",
                    tool_registry_sha256,
                ),
                "plan_sha256": _sha256(
                    "plan_sha256",
                    plan_sha256,
                ),
                "probe_sha256": _sha256(
                    "probe_sha256",
                    probe_sha256,
                ),
                "invocation_sha256": _canonical_sha256(
                    invocation.to_dict(),
                ),
            }
            if any(
                getattr(self, field_name) != expected_value
                for field_name, expected_value in expected.items()
            ):
                return False
            if self.action != invocation.action:
                return False
            if self.tool_version != invocation.version:
                return False
            if self.tool_spec_sha256 != invocation.spec_sha256:
                return False
            if (
                executor_version is not None
                and self.executor_version != executor_version
            ):
                return False
            if not hmac.compare_digest(
                self.authorization_id,
                _canonical_sha256(self._id_payload()),
            ):
                return False
            expected_signature = _hmac_signature(
                key,
                self._unsigned_dict(),
            )
            return hmac.compare_digest(
                self.signature,
                expected_signature,
            )
        except (PolicyContractError, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, Any]:
        """返回包含签名的完整授权。"""

        return {
            **self._unsigned_dict(),
            "signature": self.signature,
        }

    def _id_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "action": self.action,
            "tool_version": self.tool_version,
            "executor_version": self.executor_version,
            "risk_class": self.risk_class.value,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "tool_spec_sha256": self.tool_spec_sha256,
            "plan_sha256": self.plan_sha256,
            "probe_sha256": self.probe_sha256,
            "invocation_sha256": self.invocation_sha256,
            "budget_sha256": self.budget_sha256,
            "timeout_seconds": self.timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
            "required_authorizations": list(
                self.required_authorizations,
            ),
        }

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            **self._id_payload(),
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """确定性策略门的允许或拒绝结果。"""

    allowed: bool
    evaluated_at: float
    policy_version: str
    reason_codes: tuple[str, ...]
    authorization: ExecutionAuthorization | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "allowed": self.allowed,
            "evaluated_at": self.evaluated_at,
            "policy_version": self.policy_version,
            "reason_codes": list(self.reason_codes),
            "authorization": (
                self.authorization.to_dict()
                if self.authorization
                else None
            ),
        }


class DeterministicPolicyEngine:
    """验证全部安全门后才签发 HMAC 执行授权。"""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        hmac_key: bytes,
        policy_version: str,
        max_risk_class: RiskClass | str,
        authorization_ttl_seconds: float,
        clock: Clock = time.monotonic,
    ) -> None:
        if not isinstance(registry, ToolRegistry):
            raise PolicyContractError(
                "tool_registry_invalid",
                "registry 必须是 ToolRegistry",
            )
        if not callable(clock):
            raise PolicyContractError(
                "clock_invalid",
                "clock 必须可调用",
            )
        try:
            normalized_risk = RiskClass(max_risk_class)
        except (TypeError, ValueError) as exc:
            raise PolicyContractError(
                "risk_class_invalid",
                "max_risk_class 不是受支持的风险等级",
            ) from exc
        self._registry = registry
        self._hmac_key = _hmac_key(hmac_key)
        self._policy_version = _text(
            "policy_version",
            policy_version,
        )
        self._max_risk_class = normalized_risk
        self._authorization_ttl_seconds = _positive_number(
            "authorization_ttl_seconds",
            authorization_ttl_seconds,
        )
        self._clock = clock

    @property
    def policy_version(self) -> str:
        return self._policy_version

    def decide(
        self,
        plan: PlanProposal,
        *,
        probe_id: str,
        expected_context_sha256: str,
        expected_state_sha256: str,
        budget: RunBudget,
        granted_authorizations: Iterable[str],
    ) -> PolicyDecision:
        """评估显式输入；本方法不消耗预算或执行工具。"""

        if not isinstance(plan, PlanProposal):
            raise PolicyContractError(
                "plan_type_invalid",
                "plan 必须是 PlanProposal",
            )
        if not isinstance(budget, RunBudget):
            raise PolicyContractError(
                "budget_type_invalid",
                "budget 必须是 RunBudget",
            )
        current_context = _sha256(
            "expected_context_sha256",
            expected_context_sha256,
        )
        current_state = _sha256(
            "expected_state_sha256",
            expected_state_sha256,
        )
        granted = _string_set(
            "granted_authorizations",
            granted_authorizations,
        )
        evaluated_at = _finite_number(
            "clock",
            self._clock(),
        )
        reasons: list[str] = []

        if plan.context_sha256 != current_context:
            reasons.append("context_hash_drift")
        if plan.state_sha256 != current_state:
            reasons.append("state_hash_drift")
        if (
            plan.tool_registry_sha256
            != self._registry.canonical_sha256
        ):
            reasons.append("tool_registry_hash_drift")

        try:
            probe = plan.find_probe(probe_id)
        except AgentContractError as exc:
            reasons.append(exc.code)
            return self._rejected(
                evaluated_at=evaluated_at,
                reasons=reasons,
            )

        spec = self._validate_tool(
            probe,
            granted=granted,
            reasons=reasons,
        )
        budget_snapshot = self._validate_budget(
            probe,
            budget=budget,
            reasons=reasons,
        )

        reason_codes = tuple(dict.fromkeys(reasons))
        if reason_codes or spec is None:
            return self._rejected(
                evaluated_at=evaluated_at,
                reasons=list(reason_codes),
            )

        authorization = self._issue_authorization(
            plan=plan,
            probe=probe,
            spec=spec,
            budget_snapshot=budget_snapshot,
            evaluated_at=evaluated_at,
        )
        return PolicyDecision(
            allowed=True,
            evaluated_at=evaluated_at,
            policy_version=self._policy_version,
            reason_codes=(),
            authorization=authorization,
        )

    def _validate_tool(
        self,
        probe: ProbeProposal,
        *,
        granted: tuple[str, ...],
        reasons: list[str],
    ) -> ToolSpec | None:
        try:
            spec = self._registry.validate_invocation(
                probe.invocation,
            )
        except ToolContractError as exc:
            reasons.append(exc.code)
            return None

        missing_authorizations = sorted(
            set(spec.required_authorizations) - set(granted),
        )
        if missing_authorizations:
            reasons.append("required_authorization_missing")
        if (
            _RISK_ORDER[spec.risk_class]
            > _RISK_ORDER[self._max_risk_class]
        ):
            reasons.append("risk_class_not_allowed")
        if probe.output_limit_bytes > spec.output_limit_bytes:
            reasons.append("tool_output_limit_exceeded")
        if probe.timeout_seconds > spec.max_timeout_seconds:
            reasons.append("tool_timeout_exceeded")
        return spec

    def _validate_budget(
        self,
        probe: ProbeProposal,
        *,
        budget: RunBudget,
        reasons: list[str],
    ):
        try:
            budget.check()
        except BudgetExceeded as exc:
            reasons.append(f"budget_{exc.reason.value}")
        snapshot = budget.snapshot()
        if (
            snapshot.max_probes is not None
            and snapshot.probes_used + 1 > snapshot.max_probes
        ):
            reasons.append("probe_budget_insufficient")
        if (
            snapshot.max_output_bytes is not None
            and (
                snapshot.output_bytes_used
                + probe.output_limit_bytes
                > snapshot.max_output_bytes
            )
        ):
            reasons.append("output_budget_insufficient")
        if (
            snapshot.remaining_time is not None
            and probe.timeout_seconds > snapshot.remaining_time
        ):
            reasons.append("timeout_budget_insufficient")
        return snapshot

    def _issue_authorization(
        self,
        *,
        plan: PlanProposal,
        probe: ProbeProposal,
        spec: ToolSpec,
        budget_snapshot,
        evaluated_at: float,
    ) -> ExecutionAuthorization:
        expires_at = (
            evaluated_at + self._authorization_ttl_seconds
        )
        if budget_snapshot.deadline is not None:
            expires_at = min(expires_at, budget_snapshot.deadline)
        body = {
            "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "policy_version": self._policy_version,
            "issued_at": evaluated_at,
            "expires_at": expires_at,
            "action": spec.action,
            "tool_version": spec.version,
            "executor_version": spec.executor_version,
            "risk_class": spec.risk_class.value,
            "context_sha256": plan.context_sha256,
            "state_sha256": plan.state_sha256,
            "tool_registry_sha256": (
                self._registry.canonical_sha256
            ),
            "tool_spec_sha256": spec.canonical_sha256,
            "plan_sha256": plan.canonical_sha256,
            "probe_sha256": probe.canonical_sha256,
            "invocation_sha256": _canonical_sha256(
                probe.invocation.to_dict(),
            ),
            "budget_sha256": _canonical_sha256(
                budget_snapshot.to_dict(),
            ),
            "timeout_seconds": probe.timeout_seconds,
            "output_limit_bytes": probe.output_limit_bytes,
            "required_authorizations": list(
                spec.required_authorizations,
            ),
        }
        authorization_id = _canonical_sha256(body)
        unsigned = {
            "authorization_id": authorization_id,
            **body,
        }
        signature = _hmac_signature(
            self._hmac_key,
            unsigned,
        )
        return ExecutionAuthorization(
            authorization_id=authorization_id,
            policy_version=body["policy_version"],
            issued_at=body["issued_at"],
            expires_at=body["expires_at"],
            action=body["action"],
            tool_version=body["tool_version"],
            executor_version=body["executor_version"],
            risk_class=body["risk_class"],
            context_sha256=body["context_sha256"],
            state_sha256=body["state_sha256"],
            tool_registry_sha256=body[
                "tool_registry_sha256"
            ],
            tool_spec_sha256=body["tool_spec_sha256"],
            plan_sha256=body["plan_sha256"],
            probe_sha256=body["probe_sha256"],
            invocation_sha256=body["invocation_sha256"],
            budget_sha256=body["budget_sha256"],
            timeout_seconds=body["timeout_seconds"],
            output_limit_bytes=body["output_limit_bytes"],
            required_authorizations=tuple(
                body["required_authorizations"],
            ),
            signature=signature,
        )

    def _rejected(
        self,
        *,
        evaluated_at: float,
        reasons: list[str],
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            evaluated_at=evaluated_at,
            policy_version=self._policy_version,
            reason_codes=tuple(dict.fromkeys(reasons)),
            authorization=None,
        )


def _hmac_signature(key: bytes, value: Any) -> str:
    return hmac.new(
        key,
        _canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8"),
    ).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hmac_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise PolicyContractError(
            "hmac_key_invalid",
            "hmac_key 必须是至少 32 字节的 bytes",
            path="$.hmac_key",
        )
    return value


def _string_set(
    name: str,
    value: Iterable[str],
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise PolicyContractError(
            "string_list_invalid",
            f"{name} 必须是字符串集合",
            path=f"$.{name}",
        )
    try:
        return tuple(
            sorted(
                {
                    _text(name, item)
                    for item in value
                },
            ),
        )
    except TypeError as exc:
        raise PolicyContractError(
            "string_list_invalid",
            f"{name} 必须是字符串集合",
            path=f"$.{name}",
        ) from exc


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyContractError(
            "text_invalid",
            f"{name} 必须是非空字符串",
            path=f"$.{name}",
        )
    return value.strip()


def _sha256(name: str, value: str) -> str:
    normalized = _text(name, value).lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise PolicyContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位十六进制 SHA-256",
            path=f"$.{name}",
        )
    return normalized


def _finite_number(name: str, value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise PolicyContractError(
            "finite_number_invalid",
            f"{name} 必须是有限数字",
            path=f"$.{name}",
        )
    return float(value)


def _positive_number(name: str, value: float) -> float:
    normalized = _finite_number(name, value)
    if normalized <= 0:
        raise PolicyContractError(
            "positive_number_invalid",
            f"{name} 必须是正数",
            path=f"$.{name}",
        )
    return normalized


def _positive_integer(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyContractError(
            "positive_integer_invalid",
            f"{name} 必须是正整数",
            path=f"$.{name}",
        )
    return value
