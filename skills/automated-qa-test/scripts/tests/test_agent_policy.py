#!/usr/bin/env python3
import copy
import sys
import unittest
from dataclasses import replace
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.agent import (  # noqa: E402
    AgentContractError,
    CriticRecommendation,
    CriticReview,
    DeterministicPolicyEngine,
    ExecutionAuthorization,
    PlanProposal,
)
from qa_core.runtime import RunBudget  # noqa: E402
from qa_core.tools import (  # noqa: E402
    CleanupSemantics,
    RiskClass,
    ToolInvocation,
    ToolRegistry,
    ToolSpec,
)

CONTEXT_SHA256 = "a" * 64
STATE_SHA256 = "b" * 64
HMAC_KEY = b"policy-test-key-with-at-least-32-bytes"


class FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_spec(
    *,
    risk_class: RiskClass = RiskClass.MEDIUM,
) -> ToolSpec:
    return ToolSpec(
        action="browser.observe",
        version="1",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["dom", "api"],
                },
            },
            "required": ["target", "mode"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["ok", "failed"],
                },
            },
            "required": ["status"],
            "additionalProperties": False,
        },
        capabilities=("browser.dom",),
        risk_class=risk_class,
        required_authorizations=("isolated_test_environment",),
        read=("dom",),
        write=("run_scratch",),
        side_effects=("browser_navigation",),
        reversible=True,
        idempotent=True,
        default_timeout_seconds=10,
        max_timeout_seconds=30,
        output_limit_bytes=4096,
        evidence_types=("dom_snapshot",),
        executor_version="playwright@1",
        cleanup_semantics=CleanupSemantics.BEST_EFFORT,
    )


def plan_payload(registry: ToolRegistry) -> dict:
    return {
        "proposal_id": "plan-001",
        "context_sha256": CONTEXT_SHA256,
        "state_sha256": STATE_SHA256,
        "tool_registry_sha256": registry.canonical_sha256,
        "model_id": "planner-model@2026-07",
        "objective": "验证结算页不会重复提交订单",
        "hypotheses": [
            {
                "hypothesis_id": "H1",
                "statement": "快速重复点击可能产生重复订单",
                "evidence_refs": ["requirement.md#R1"],
            },
        ],
        "evidence_refs": ["requirement.md#R1"],
        "probes": [
            {
                "probe_id": "P1",
                "context_sha256": CONTEXT_SHA256,
                "state_sha256": STATE_SHA256,
                "tool_registry_sha256": registry.canonical_sha256,
                "model_id": "planner-model@2026-07",
                "hypothesis_ids": ["H1"],
                "evidence_refs": ["requirement.md#R1"],
                "rationale": "观察提交按钮和请求序列",
                "invocation": {
                    "action": "browser.observe",
                    "arguments": {
                        "target": "/checkout",
                        "mode": "dom",
                    },
                },
                "timeout_seconds": 10,
                "output_limit_bytes": 512,
            },
        ],
    }


def make_plan(registry: ToolRegistry) -> PlanProposal:
    return PlanProposal.from_model_input(
        plan_payload(registry),
        registry=registry,
    )


def make_budget(
    clock: FakeClock,
    *,
    total_timeout: float = 60,
    max_probes: int = 2,
    max_output_bytes: int = 8192,
) -> RunBudget:
    return RunBudget(
        total_timeout=total_timeout,
        max_probes=max_probes,
        max_output_bytes=max_output_bytes,
        clock=clock,
    )


def make_engine(
    registry: ToolRegistry,
    clock: FakeClock,
    *,
    max_risk_class: RiskClass = RiskClass.MEDIUM,
) -> DeterministicPolicyEngine:
    return DeterministicPolicyEngine(
        registry=registry,
        hmac_key=HMAC_KEY,
        policy_version="policy@1",
        max_risk_class=max_risk_class,
        authorization_ttl_seconds=20,
        clock=clock,
    )


class AgentProposalContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ToolRegistry([make_spec()])

    def test_plan_and_probe_bind_all_current_inputs(self) -> None:
        plan = make_plan(self.registry)
        probe = plan.probes[0]

        self.assertEqual(plan.context_sha256, CONTEXT_SHA256)
        self.assertEqual(plan.state_sha256, STATE_SHA256)
        self.assertEqual(
            plan.tool_registry_sha256,
            self.registry.canonical_sha256,
        )
        self.assertEqual(probe.context_sha256, plan.context_sha256)
        self.assertEqual(probe.state_sha256, plan.state_sha256)
        self.assertEqual(
            probe.tool_registry_sha256,
            plan.tool_registry_sha256,
        )
        self.assertEqual(probe.hypothesis_ids, ("H1",))
        self.assertEqual(
            plan.hypotheses[0].evidence_refs,
            ("requirement.md#R1",),
        )
        self.assertEqual(len(plan.canonical_sha256), 64)
        self.assertEqual(len(probe.canonical_sha256), 64)

    def test_unknown_and_authority_fields_are_rejected(self) -> None:
        unknown = plan_payload(self.registry)
        unknown["temperature"] = 0.1
        with self.assertRaises(AgentContractError) as unknown_error:
            PlanProposal.from_model_input(
                unknown,
                registry=self.registry,
            )
        self.assertEqual(
            unknown_error.exception.code,
            "proposal_fields_unknown",
        )

        forbidden = plan_payload(self.registry)
        forbidden["authorization"] = "model-approved"
        with self.assertRaises(AgentContractError) as authority_error:
            PlanProposal.from_model_input(
                forbidden,
                registry=self.registry,
            )
        self.assertEqual(
            authority_error.exception.code,
            "model_field_forbidden",
        )

        nested_shell = plan_payload(self.registry)
        nested_shell["probes"][0]["invocation"]["arguments"]["shell"] = True
        with self.assertRaises(AgentContractError) as shell_error:
            PlanProposal.from_model_input(
                nested_shell,
                registry=self.registry,
            )
        self.assertEqual(
            shell_error.exception.code,
            "model_field_forbidden",
        )

        wrong_array = plan_payload(self.registry)
        wrong_array["evidence_refs"] = "requirement.md#R1"
        with self.assertRaises(AgentContractError) as array_error:
            PlanProposal.from_model_input(
                wrong_array,
                registry=self.registry,
            )
        self.assertEqual(
            array_error.exception.code,
            "model_array_invalid",
        )

    def test_probe_cannot_reference_an_unknown_hypothesis(self) -> None:
        payload = plan_payload(self.registry)
        payload["probes"][0]["hypothesis_ids"] = ["missing"]

        with self.assertRaises(AgentContractError) as caught:
            PlanProposal.from_model_input(
                payload,
                registry=self.registry,
            )

        self.assertEqual(caught.exception.code, "hypothesis_ref_unknown")

    def test_critic_review_is_strict_and_has_no_approval_authority(self) -> None:
        plan = make_plan(self.registry)
        review = CriticReview.from_model_input(
            {
                "review_id": "review-1",
                "plan_sha256": plan.canonical_sha256,
                "context_sha256": CONTEXT_SHA256,
                "state_sha256": STATE_SHA256,
                "tool_registry_sha256": self.registry.canonical_sha256,
                "model_id": "critic-model@2026-07",
                "recommendation": "revise",
                "hypothesis_ids": ["H1"],
                "evidence_refs": ["requirement.md#R1"],
                "findings": ["需要补充 API 请求序列证据"],
            },
        )

        self.assertEqual(
            review.recommendation,
            CriticRecommendation.REVISE,
        )
        self.assertFalse(hasattr(review, "authorization"))

        payload = review.to_dict()
        payload["signature"] = "forged"
        with self.assertRaises(AgentContractError) as caught:
            CriticReview.from_model_input(payload)
        self.assertEqual(
            caught.exception.code,
            "model_field_forbidden",
        )


class DeterministicPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.registry = ToolRegistry([make_spec()])
        self.plan = make_plan(self.registry)
        self.engine = make_engine(self.registry, self.clock)

    def decide(
        self,
        *,
        plan: PlanProposal | None = None,
        budget: RunBudget | None = None,
        granted_authorizations: tuple[str, ...] = (
            "isolated_test_environment",
        ),
        expected_context_sha256: str = CONTEXT_SHA256,
        expected_state_sha256: str = STATE_SHA256,
    ):
        return self.engine.decide(
            plan or self.plan,
            probe_id="P1",
            expected_context_sha256=expected_context_sha256,
            expected_state_sha256=expected_state_sha256,
            budget=budget or make_budget(self.clock),
            granted_authorizations=granted_authorizations,
        )

    def test_legal_authorization_is_deterministic_and_independently_verified(
        self,
    ) -> None:
        budget = make_budget(self.clock)

        first = self.decide(budget=budget)
        second = self.decide(budget=budget)

        self.assertTrue(first.allowed)
        self.assertEqual(first.reason_codes, ())
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(budget.snapshot().probes_used, 0)
        authorization = first.authorization
        self.assertIsNotNone(authorization)
        assert authorization is not None
        probe = self.plan.probes[0]
        self.assertTrue(
            authorization.verify(
                hmac_key=HMAC_KEY,
                invocation=probe.invocation,
                context_sha256=CONTEXT_SHA256,
                state_sha256=STATE_SHA256,
                tool_registry_sha256=self.registry.canonical_sha256,
                plan_sha256=self.plan.canonical_sha256,
                probe_sha256=probe.canonical_sha256,
                policy_version="policy@1",
                now=self.clock(),
            ),
        )

    def test_unknown_action_is_rejected_before_authorization(self) -> None:
        probe = self.plan.probes[0]
        unknown_invocation = ToolInvocation(
            action="missing.tool",
            version="1",
            arguments={
                "target": "/checkout",
                "mode": "dom",
            },
            spec_sha256="c" * 64,
        )
        unknown_probe = replace(
            probe,
            invocation=unknown_invocation,
        )
        unknown_plan = replace(
            self.plan,
            probes=(unknown_probe,),
        )

        decision = self.decide(plan=unknown_plan)

        self.assertFalse(decision.allowed)
        self.assertIn("unknown_action", decision.reason_codes)
        self.assertIsNone(decision.authorization)

    def test_missing_required_authorization_is_rejected(self) -> None:
        decision = self.decide(granted_authorizations=())

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_codes,
            ("required_authorization_missing",),
        )
        self.assertIsNone(decision.authorization)

    def test_context_and_tool_hash_drift_are_rejected(self) -> None:
        context_drift = self.decide(
            expected_context_sha256="d" * 64,
        )
        self.assertIn(
            "context_hash_drift",
            context_drift.reason_codes,
        )

        probe = self.plan.probes[0]
        drifted_invocation = replace(
            probe.invocation,
            spec_sha256="e" * 64,
        )
        drifted_probe = replace(
            probe,
            invocation=drifted_invocation,
        )
        drifted_plan = replace(
            self.plan,
            probes=(drifted_probe,),
        )
        spec_drift = self.decide(plan=drifted_plan)
        self.assertIn("tool_spec_drift", spec_drift.reason_codes)

    def test_budget_shortages_are_reported_without_consuming_budget(self) -> None:
        budget = make_budget(
            self.clock,
            total_timeout=5,
            max_probes=0,
            max_output_bytes=100,
        )

        decision = self.decide(budget=budget)

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_codes,
            (
                "probe_budget_insufficient",
                "output_budget_insufficient",
                "timeout_budget_insufficient",
            ),
        )
        self.assertEqual(budget.snapshot().probes_used, 0)
        self.assertEqual(budget.snapshot().output_bytes_used, 0)

    def test_tool_timeout_output_and_risk_limits_are_enforced(self) -> None:
        probe = self.plan.probes[0]
        over_limit_probe = replace(
            probe,
            timeout_seconds=31,
            output_limit_bytes=4097,
        )
        over_limit_plan = replace(
            self.plan,
            probes=(over_limit_probe,),
        )
        limits = self.decide(plan=over_limit_plan)
        self.assertEqual(
            limits.reason_codes,
            (
                "tool_output_limit_exceeded",
                "tool_timeout_exceeded",
            ),
        )

        high_registry = ToolRegistry(
            [make_spec(risk_class=RiskClass.HIGH)],
        )
        high_plan = make_plan(high_registry)
        high_engine = make_engine(
            high_registry,
            self.clock,
            max_risk_class=RiskClass.MEDIUM,
        )
        risk = high_engine.decide(
            high_plan,
            probe_id="P1",
            expected_context_sha256=CONTEXT_SHA256,
            expected_state_sha256=STATE_SHA256,
            budget=make_budget(self.clock),
            granted_authorizations=("isolated_test_environment",),
        )
        self.assertEqual(
            risk.reason_codes,
            ("risk_class_not_allowed",),
        )

    def test_signature_or_binding_tampering_fails_verification(self) -> None:
        decision = self.decide()
        authorization = decision.authorization
        assert authorization is not None
        payload = copy.deepcopy(authorization.to_dict())
        payload["output_limit_bytes"] += 1
        tampered = ExecutionAuthorization.from_dict(payload)
        forged_signature_payload = copy.deepcopy(
            authorization.to_dict(),
        )
        forged_signature_payload["signature"] = "0" * 64
        forged_signature = ExecutionAuthorization.from_dict(
            forged_signature_payload,
        )
        probe = self.plan.probes[0]

        for invalid_authorization in (
            tampered,
            forged_signature,
        ):
            with self.subTest(
                authorization=invalid_authorization,
            ):
                self.assertFalse(
                    invalid_authorization.verify(
                        hmac_key=HMAC_KEY,
                        invocation=probe.invocation,
                        context_sha256=CONTEXT_SHA256,
                        state_sha256=STATE_SHA256,
                        tool_registry_sha256=(
                            self.registry.canonical_sha256
                        ),
                        plan_sha256=self.plan.canonical_sha256,
                        probe_sha256=probe.canonical_sha256,
                        policy_version="policy@1",
                        now=self.clock(),
                    ),
                )
        self.assertFalse(
            authorization.verify(
                hmac_key=b"x" * 32,
                invocation=probe.invocation,
                context_sha256=CONTEXT_SHA256,
                state_sha256=STATE_SHA256,
                tool_registry_sha256=self.registry.canonical_sha256,
                plan_sha256=self.plan.canonical_sha256,
                probe_sha256=probe.canonical_sha256,
                policy_version="policy@1",
                now=self.clock(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
