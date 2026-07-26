#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.tools import (  # noqa: E402
    CleanupSemantics,
    RiskClass,
    ToolContractError,
    ToolInvocation,
    ToolRegistry,
    ToolSpec,
)


def input_schema(*, modes: tuple[str, ...] = ("dom", "api")) -> dict:
    return {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "mode": {"type": "string", "enum": list(modes)},
            "attempts": {"type": "integer"},
            "options": {
                "type": "object",
                "properties": {
                    "trace": {"type": "boolean"},
                },
                "required": [],
                "additionalProperties": False,
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": ["target", "mode"],
        "additionalProperties": False,
    }


def output_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["ok", "failed"],
            },
            "bytes": {"type": "integer"},
        },
        "required": ["status"],
        "additionalProperties": False,
    }


def make_spec(
    action: str = "browser.observe",
    *,
    modes: tuple[str, ...] = ("dom", "api"),
    capabilities: tuple[str, ...] = ("network.observe", "browser.dom"),
) -> ToolSpec:
    return ToolSpec(
        action=action,
        version="2.1",
        input_schema=input_schema(modes=modes),
        output_schema=output_schema(),
        capabilities=capabilities,
        risk_class=RiskClass.LOW,
        required_authorizations=("isolated_test_environment",),
        read=("dom", "network"),
        write=("run_scratch",),
        side_effects=("browser_navigation",),
        reversible=True,
        idempotent=True,
        default_timeout_seconds=10,
        max_timeout_seconds=30,
        output_limit_bytes=4096,
        evidence_types=("dom_snapshot", "network_trace"),
        executor_version="playwright@1",
        cleanup_semantics=CleanupSemantics.BEST_EFFORT,
    )


class ToolSpecTests(unittest.TestCase):
    def test_spec_covers_execution_and_effect_metadata(self) -> None:
        spec = make_spec()

        self.assertEqual(
            spec.to_dict(),
            {
                "action": "browser.observe",
                "version": "2.1",
                "input_schema": input_schema(),
                "output_schema": output_schema(),
                "capabilities": ["browser.dom", "network.observe"],
                "risk_class": "low",
                "required_authorizations": ["isolated_test_environment"],
                "read": ["dom", "network"],
                "write": ["run_scratch"],
                "side_effects": ["browser_navigation"],
                "reversible": True,
                "idempotent": True,
                "default_timeout_seconds": 10.0,
                "max_timeout_seconds": 30.0,
                "output_limit_bytes": 4096,
                "evidence_types": ["dom_snapshot", "network_trace"],
                "executor_version": "playwright@1",
                "cleanup_semantics": "best_effort",
            },
        )
        self.assertEqual(len(spec.canonical_sha256), 64)

    def test_object_schemas_must_be_explicitly_closed(self) -> None:
        invalid_input = input_schema()
        invalid_input.pop("additionalProperties")

        with self.assertRaises(ToolContractError) as caught:
            ToolSpec(
                action="invalid.input",
                version="1",
                input_schema=invalid_input,
                output_schema=output_schema(),
                capabilities=(),
                risk_class="low",
                required_authorizations=(),
                read=(),
                write=(),
                side_effects=(),
                reversible=True,
                idempotent=True,
                default_timeout_seconds=1,
                max_timeout_seconds=1,
                output_limit_bytes=1,
                evidence_types=(),
                executor_version="executor@1",
                cleanup_semantics="none",
            )

        self.assertEqual(caught.exception.code, "schema_not_closed")
        self.assertEqual(caught.exception.path, "$.input_schema")

    def test_nested_objects_and_required_fields_are_schema_checked(self) -> None:
        nested_open = input_schema()
        nested_open["properties"]["options"].pop("additionalProperties")
        with self.assertRaises(ToolContractError) as open_error:
            make_spec_with_schema(nested_open)
        self.assertEqual(open_error.exception.code, "schema_not_closed")

        unknown_required = input_schema()
        unknown_required["required"].append("missing")
        with self.assertRaises(ToolContractError) as required_error:
            make_spec_with_schema(unknown_required)
        self.assertEqual(required_error.exception.code, "schema_required_unknown")

    def test_spec_takes_an_immutable_schema_snapshot(self) -> None:
        schema = input_schema()
        spec = make_spec_with_schema(schema)
        original_hash = spec.canonical_sha256

        schema["properties"]["target"]["type"] = "integer"
        schema["properties"]["new"] = {"type": "boolean"}

        self.assertEqual(spec.input_schema["properties"]["target"]["type"], "string")
        self.assertNotIn("new", spec.input_schema["properties"])
        self.assertEqual(spec.canonical_sha256, original_hash)


def make_spec_with_schema(schema: dict) -> ToolSpec:
    return ToolSpec(
        action="custom.tool",
        version="1",
        input_schema=schema,
        output_schema=output_schema(),
        capabilities=(),
        risk_class="medium",
        required_authorizations=(),
        read=(),
        write=(),
        side_effects=(),
        reversible=False,
        idempotent=False,
        default_timeout_seconds=2,
        max_timeout_seconds=4,
        output_limit_bytes=128,
        evidence_types=(),
        executor_version="custom@1",
        cleanup_semantics="required",
    )


class ToolRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = make_spec()
        self.registry = ToolRegistry([self.spec])

    def test_duplicate_and_unknown_actions_fail_closed(self) -> None:
        with self.assertRaises(ToolContractError) as duplicate:
            self.registry.register(make_spec())
        self.assertEqual(duplicate.exception.code, "duplicate_action")

        with self.assertRaises(ToolContractError) as unknown:
            self.registry.get("missing.action")
        self.assertEqual(unknown.exception.code, "unknown_action")

    def test_registry_hash_is_independent_of_registration_order(self) -> None:
        alpha = make_spec("alpha.read")
        beta = make_spec("beta.read")

        first = ToolRegistry([alpha, beta])
        second = ToolRegistry([beta, alpha])

        self.assertEqual(first.canonical_sha256, second.canonical_sha256)
        self.assertEqual(
            [item["action"] for item in first.to_manifest()["tools"]],
            ["alpha.read", "beta.read"],
        )

    def test_spec_hash_normalizes_unordered_metadata(self) -> None:
        first = make_spec(
            capabilities=("network.observe", "browser.dom"),
        )
        second = make_spec(
            capabilities=("browser.dom", "network.observe"),
        )

        self.assertEqual(first.canonical_sha256, second.canonical_sha256)

    def test_model_input_only_creates_a_hash_bound_invocation(self) -> None:
        invocation = self.registry.invocation_from_model(
            {
                "action": "browser.observe",
                "arguments": {
                    "target": "/checkout",
                    "mode": "dom",
                },
            },
        )

        self.assertIsInstance(invocation, ToolInvocation)
        self.assertEqual(invocation.version, self.spec.version)
        self.assertEqual(invocation.spec_sha256, self.spec.canonical_sha256)
        self.assertFalse(hasattr(invocation, "authorization"))
        self.assertIs(self.registry.validate_invocation(invocation), self.spec)

        with self.assertRaises(ToolContractError) as caught:
            self.registry.invocation_from_model(
                {
                    "action": "browser.observe",
                    "arguments": {
                        "target": "/checkout",
                        "mode": "dom",
                    },
                    "authorization": "model-approved",
                },
            )
        self.assertEqual(caught.exception.code, "model_fields_unknown")

    def test_preflight_rejects_unknown_type_enum_and_required_drift(self) -> None:
        invalid_cases = (
            (
                {
                    "target": "/checkout",
                    "mode": "dom",
                    "unexpected": True,
                },
                "additional_property",
            ),
            (
                {
                    "target": "/checkout",
                    "mode": "dom",
                    "attempts": True,
                },
                "type_mismatch",
            ),
            (
                {
                    "target": "/checkout",
                    "mode": "shell",
                },
                "enum_mismatch",
            ),
            (
                {
                    "target": "/checkout",
                },
                "required_missing",
            ),
            (
                {
                    "target": "/checkout",
                    "mode": "dom",
                    "options": {"trace": True, "hidden": True},
                },
                "additional_property",
            ),
        )

        for arguments, expected_code in invalid_cases:
            with self.subTest(expected_code=expected_code):
                invocation = ToolInvocation(
                    action=self.spec.action,
                    version=self.spec.version,
                    arguments=arguments,
                    spec_sha256=self.spec.canonical_sha256,
                )
                with self.assertRaises(ToolContractError) as caught:
                    self.registry.validate_invocation(invocation)
                self.assertEqual(caught.exception.code, expected_code)

    def test_spec_drift_invalidates_an_existing_invocation(self) -> None:
        invocation = self.registry.invocation_from_model(
            {
                "action": self.spec.action,
                "arguments": {
                    "target": "/checkout",
                    "mode": "dom",
                },
            },
        )
        changed_registry = ToolRegistry(
            [
                make_spec(
                    modes=("dom", "api", "worker"),
                ),
            ],
        )

        with self.assertRaises(ToolContractError) as caught:
            changed_registry.validate_invocation(invocation)

        self.assertEqual(caught.exception.code, "tool_spec_drift")

    def test_output_uses_the_same_strict_schema_boundary(self) -> None:
        invocation = self.registry.invocation_from_model(
            {
                "action": self.spec.action,
                "arguments": {
                    "target": "/checkout",
                    "mode": "api",
                },
            },
        )
        self.registry.validate_output(
            invocation,
            {
                "status": "ok",
                "bytes": 32,
            },
        )

        with self.assertRaises(ToolContractError) as extra:
            self.registry.validate_output(
                invocation,
                {
                    "status": "ok",
                    "debug": "must not cross the contract",
                },
            )
        self.assertEqual(extra.exception.code, "additional_property")

        with self.assertRaises(ToolContractError) as invalid_enum:
            self.registry.validate_output(
                invocation,
                {
                    "status": "unknown",
                },
            )
        self.assertEqual(invalid_enum.exception.code, "enum_mismatch")


if __name__ == "__main__":
    unittest.main()
