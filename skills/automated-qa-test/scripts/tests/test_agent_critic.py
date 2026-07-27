#!/usr/bin/env python3
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import agent_critic_cli as critic_cli  # noqa: E402
import qa_common  # noqa: E402
from qa_core.planning import (  # noqa: E402
    CriticContractError,
    CriticRequest,
    DeterministicProbeCritic,
)
from qa_core.planning.critic import _checked_fsum  # noqa: E402
from qa_core.tools import build_default_tool_registry  # noqa: E402

CLI_PATH = SCRIPT_DIR / "agent_critic_cli.py"


def observation(
    observation_id: str,
    probability: float,
    hypothesis_id: str,
    posterior: float,
) -> dict:
    return {
        "observation_id": observation_id,
        "probability": probability,
        "posteriors": [
            {
                "hypothesis_id": hypothesis_id,
                "defect_probability": posterior,
            }
        ],
    }


def candidate(
    probe_id: str,
    *,
    fingerprint: str,
    hypothesis_id: str,
    gap_id: str,
    posterior_high: float,
    posterior_low: float,
    duration: float = 10,
    output_bytes: int = 1024,
) -> dict:
    spec = build_default_tool_registry().get("expectText")
    return {
        "probe_id": probe_id,
        "action": spec.action,
        "arguments": {"text": fingerprint},
        "tool_version": spec.version,
        "tool_spec_sha256": spec.canonical_sha256,
        "hypothesis_ids": [hypothesis_id],
        "evidence_gap_ids": [gap_id],
        "expected_observations": [
            observation("positive", 0.5, hypothesis_id, posterior_high),
            observation("negative", 0.5, hypothesis_id, posterior_low),
        ],
        "estimated_cost": {
            "duration_seconds": duration,
            "output_bytes": output_bytes,
        },
    }


def fingerprint_for(value: str) -> str:
    spec = build_default_tool_registry().get("expectText")
    encoded = json.dumps(
        {
            "action": spec.action,
            "arguments": {"text": value},
            "tool_version": spec.version,
            "tool_spec_sha256": spec.canonical_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def request_payload() -> dict:
    registry = build_default_tool_registry()
    return {
        "schema_version": 1,
        "request_id": "critic-request-001",
        "plan_sha256": "a" * 64,
        "context_sha256": "b" * 64,
        "state_sha256": "c" * 64,
        "tool_registry_sha256": registry.canonical_sha256,
        "hypotheses": [
            {
                "hypothesis_id": "H1",
                "statement": "快速重复提交会产生重复订单",
                "prior_defect_probability": 0.5,
                "defect_impact": 1.0,
            },
            {
                "hypothesis_id": "H2",
                "statement": "错误提示可能缺少可访问名称",
                "prior_defect_probability": 0.2,
                "defect_impact": 0.5,
            },
        ],
        "evidence_gaps": [
            {
                "gap_id": "G1",
                "hypothesis_id": "H1",
                "statement": "缺少并发请求序列",
                "evidence_refs": ["requirements.md#R1"],
                "conflict_level": 0.9,
            },
            {
                "gap_id": "G2",
                "hypothesis_id": "H1",
                "statement": "已有截图与 API 日志冲突",
                "evidence_refs": ["evidence/api.json", "evidence/ui.png"],
                "conflict_level": 0.2,
            },
            {
                "gap_id": "G3",
                "hypothesis_id": "H2",
                "statement": "缺少可访问树快照",
                "evidence_refs": ["requirements.md#R2"],
                "conflict_level": 0.5,
            },
        ],
        "candidates": [
            candidate(
                "P-high-information",
                fingerprint="1" * 64,
                hypothesis_id="H1",
                gap_id="G1",
                posterior_high=0.9,
                posterior_low=0.1,
            ),
            candidate(
                "P-low-conflict",
                fingerprint="2" * 64,
                hypothesis_id="H1",
                gap_id="G2",
                posterior_high=0.7,
                posterior_low=0.3,
            ),
            candidate(
                "P-repeated",
                fingerprint="3" * 64,
                hypothesis_id="H1",
                gap_id="G1",
                posterior_high=0.9,
                posterior_low=0.1,
            ),
            candidate(
                "P-budget-exceeded",
                fingerprint="4" * 64,
                hypothesis_id="H1",
                gap_id="G1",
                posterior_high=0.99,
                posterior_low=0.01,
                duration=200,
            ),
        ],
        "history": [
            {
                "probe_fingerprint_sha256": fingerprint_for("3" * 64),
                "attempts": 3,
                "no_progress_attempts": 3,
            }
        ],
        "budget": {
            "remaining_seconds": 60,
            "remaining_probes": 2,
            "remaining_output_bytes": 8192,
        },
    }


class CriticContractTests(unittest.TestCase):
    def test_ranking_is_explainable_stable_and_not_authorization(self) -> None:
        request = CriticRequest.from_dict(request_payload())
        critic = DeterministicProbeCritic()

        first = critic.rank(request)
        second = critic.rank(
            CriticRequest.from_dict(copy.deepcopy(request_payload()))
        )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.canonical_sha256, second.canonical_sha256)
        self.assertEqual(len(first.canonical_sha256), 64)
        self.assertTrue(first.not_authorization)
        self.assertFalse(first.admission_allowed)
        self.assertFalse(first.history_authoritative)
        self.assertEqual(
            first.policy_boundary,
            "candidate_requires_separate_policy_decision",
        )
        rankings = first.ranked_probes
        self.assertEqual(rankings[0].probe_id, "P-high-information")
        self.assertEqual(rankings[-1].probe_id, "P-budget-exceeded")
        self.assertFalse(rankings[-1].budget_feasible)
        self.assertEqual(
            rankings[-1].suggestion,
            "defer_budget_exceeded",
        )
        self.assertTrue(
            all(item.not_authorization for item in rankings)
        )
        low_conflict = next(
            item
            for item in rankings
            if item.probe_id == "P-low-conflict"
        )
        self.assertGreater(
            rankings[0].signals["normalized_information_gain"],
            low_conflict.signals["normalized_information_gain"],
        )
        repeated = next(
            item for item in rankings if item.probe_id == "P-repeated"
        )
        self.assertLess(
            repeated.weighted_contributions["duplicate_penalty"],
            0,
        )
        self.assertLess(
            repeated.weighted_contributions["no_progress_penalty"],
            0,
        )
        self.assertTrue(
            all(
                not item.history_authoritative
                for item in rankings
            )
        )
        self.assertTrue(
            all(
                item.signals["duplicate_level"] == 1.0
                for item in rankings
            )
        )
        self.assertIn(
            "Policy must independently authorize any execution.",
            rankings[0].explanation,
        )
        self.assertNotIn("authorization", first.to_dict())
        self.assertEqual(
            first.to_dict()["anti_repeat_policy"],
            "conservative_floor_for_unverified_history",
        )

    def test_equivalent_input_order_has_same_request_and_result_hash(self) -> None:
        original = request_payload()
        reordered = copy.deepcopy(original)
        for field in (
            "hypotheses",
            "evidence_gaps",
            "candidates",
            "history",
        ):
            reordered[field].reverse()

        first_request = CriticRequest.from_dict(original)
        second_request = CriticRequest.from_dict(reordered)
        first = DeterministicProbeCritic().rank(first_request)
        second = DeterministicProbeCritic().rank(second_request)

        self.assertEqual(
            first_request.canonical_sha256,
            second_request.canonical_sha256,
        )
        self.assertEqual(first.canonical_sha256, second.canonical_sha256)

    def test_unknown_fields_fail_closed_at_every_level(self) -> None:
        locations = (
            ((), "authorization"),
            (("hypotheses", 0), "confidence_note"),
            (("evidence_gaps", 0), "tool"),
            (("candidates", 0), "approved"),
            (("candidates", 0), "probe_fingerprint_sha256"),
            (("candidates", 0, "estimated_cost"), "currency"),
            (
                ("candidates", 0, "expected_observations", 0),
                "signature",
            ),
            (
                (
                    "candidates",
                    0,
                    "expected_observations",
                    0,
                    "posteriors",
                    0,
                ),
                "reason",
            ),
            (("history", 0), "last_result"),
            (("budget",), "tokens"),
        )
        for path, field in locations:
            with self.subTest(path=path, field=field):
                payload = request_payload()
                target = payload
                for segment in path:
                    target = target[segment]
                target[field] = "malicious"
                with self.assertRaises(CriticContractError) as caught:
                    CriticRequest.from_dict(payload)
                self.assertEqual(caught.exception.code, "fields_unknown")

    def test_nan_infinity_and_negative_cost_fail_closed(self) -> None:
        mutations = (
            (
                ("hypotheses", 0, "prior_defect_probability"),
                float("nan"),
                "number_not_finite",
            ),
            (
                (
                    "candidates",
                    0,
                    "expected_observations",
                    0,
                    "probability",
                ),
                float("inf"),
                "number_not_finite",
            ),
            (
                (
                    "candidates",
                    0,
                    "estimated_cost",
                    "duration_seconds",
                ),
                -1,
                "number_out_of_range",
            ),
            (
                (
                    "candidates",
                    0,
                    "estimated_cost",
                    "output_bytes",
                ),
                -1,
                "integer_out_of_range",
            ),
        )
        for path, value, code in mutations:
            with self.subTest(path=path):
                payload = request_payload()
                target = payload
                for segment in path[:-1]:
                    target = target[segment]
                target[path[-1]] = value
                with self.assertRaises(CriticContractError) as caught:
                    CriticRequest.from_dict(payload)
                self.assertEqual(caught.exception.code, code)

    def test_candidate_must_close_hypothesis_gap_reference_graph(self) -> None:
        cases = (
            (
                "unknown hypothesis",
                lambda payload: payload["candidates"][0][
                    "hypothesis_ids"
                ].__setitem__(0, "missing"),
                "candidate_hypothesis_unknown",
            ),
            (
                "unknown gap",
                lambda payload: payload["candidates"][0][
                    "evidence_gap_ids"
                ].__setitem__(0, "missing"),
                "candidate_gap_unknown",
            ),
            (
                "unrelated gap",
                lambda payload: payload["candidates"][0][
                    "evidence_gap_ids"
                ].__setitem__(0, "G3"),
                "candidate_gap_link_missing",
            ),
        )
        for name, mutate, code in cases:
            with self.subTest(name=name):
                payload = request_payload()
                mutate(payload)
                with self.assertRaises(CriticContractError) as caught:
                    CriticRequest.from_dict(payload)
                self.assertEqual(caught.exception.code, code)

    def test_probability_model_must_be_complete_and_bayes_consistent(
        self,
    ) -> None:
        invalid_sum = request_payload()
        invalid_sum["candidates"][0]["expected_observations"][0][
            "probability"
        ] = 0.8
        with self.assertRaises(CriticContractError) as caught:
            CriticRequest.from_dict(invalid_sum)
        self.assertEqual(
            caught.exception.code,
            "observation_probability_sum_invalid",
        )

        inconsistent = request_payload()
        inconsistent["candidates"][0]["expected_observations"][0][
            "posteriors"
        ][0]["defect_probability"] = 0.8
        with self.assertRaises(CriticContractError) as caught:
            CriticRequest.from_dict(inconsistent)
        self.assertEqual(
            caught.exception.code,
            "posterior_prior_inconsistent",
        )

        missing_posterior = request_payload()
        missing_posterior["candidates"][0]["expected_observations"][0][
            "posteriors"
        ][0]["hypothesis_id"] = "H2"
        with self.assertRaises(CriticContractError) as caught:
            CriticRequest.from_dict(missing_posterior)
        self.assertEqual(
            caught.exception.code,
            "posterior_hypothesis_set_mismatch",
        )

    def test_zero_remaining_budget_is_valid_but_defers_all_candidates(
        self,
    ) -> None:
        payload = request_payload()
        payload["budget"] = {
            "remaining_seconds": 0,
            "remaining_probes": 0,
            "remaining_output_bytes": 0,
        }

        result = DeterministicProbeCritic().rank(
            CriticRequest.from_dict(payload)
        )

        self.assertTrue(
            all(not item.budget_feasible for item in result.ranked_probes)
        )
        self.assertTrue(
            all(
                item.suggestion == "defer_budget_exceeded"
                for item in result.ranked_probes
            )
        )

    def test_fingerprint_is_derived_and_tool_bindings_fail_closed(
        self,
    ) -> None:
        original = request_payload()
        changed = copy.deepcopy(original)
        changed["candidates"][0]["arguments"]["text"] = "changed"
        first = CriticRequest.from_dict(original)
        second = CriticRequest.from_dict(changed)
        first_probe = next(
            item
            for item in first.candidates
            if item.probe_id == "P-high-information"
        )
        second_probe = next(
            item
            for item in second.candidates
            if item.probe_id == "P-high-information"
        )
        self.assertNotEqual(
            first_probe.probe_fingerprint_sha256,
            second_probe.probe_fingerprint_sha256,
        )

        forged_spec = request_payload()
        forged_spec["candidates"][0]["tool_spec_sha256"] = "0" * 64
        with self.assertRaises(CriticContractError) as spec_error:
            CriticRequest.from_dict(forged_spec)
        self.assertEqual(
            spec_error.exception.code,
            "tool_invocation_invalid",
        )

        forged_registry = request_payload()
        forged_registry["tool_registry_sha256"] = "0" * 64
        with self.assertRaises(CriticContractError) as registry_error:
            CriticRequest.from_dict(forged_registry)
        self.assertEqual(
            registry_error.exception.code,
            "tool_registry_drift",
        )

    def test_business_numeric_bounds_fail_closed(self) -> None:
        payload = request_payload()
        payload["budget"]["remaining_seconds"] = 604_801
        with self.assertRaises(CriticContractError) as bounded:
            CriticRequest.from_dict(payload)
        self.assertEqual(
            bounded.exception.code,
            "number_out_of_range",
        )

        with self.assertRaises(CriticContractError) as overflow:
            _checked_fsum((1e308, 1e308), path="$.test")
        self.assertEqual(
            overflow.exception.code,
            "numeric_sum_overflow",
        )


class AgentCriticCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self,
        payload: dict,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        request_path = self.run_dir / "critic-request.json"
        output_path = self.run_dir / "critic-result.json"
        request_path.write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
        return self.run_cli_path(request_path, output_path)

    def run_cli_path(
        self,
        request_path: Path,
        output_path: Path,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        process = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--request",
                str(request_path),
                "--out",
                str(output_path),
            ],
            text=True,
            capture_output=True,
        )
        result = json.loads(output_path.read_text(encoding="utf-8"))
        return process, result

    def test_cli_emits_hash_bound_advice_only(self) -> None:
        process, result = self.run_cli(request_payload())

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["not_authorization"])
        self.assertEqual(len(result["request_sha256"]), 64)
        self.assertEqual(len(result["result_sha256"]), 64)
        self.assertEqual(
            result["ranked_probes"][0]["probe_id"],
            "P-high-information",
        )

    def test_cli_rejects_non_finite_number_without_partial_advice(self) -> None:
        payload = request_payload()
        payload["candidates"][0]["estimated_cost"][
            "duration_seconds"
        ] = float("nan")

        process, result = self.run_cli(payload)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["not_authorization"])
        self.assertEqual(
            result["error"]["code"],
            "json_number_nonfinite",
        )
        self.assertNotIn("ranked_probes", result)
        self.assertNotIn("Traceback", process.stderr)

    def test_cli_rejects_duplicate_keys_symlinks_and_large_files(
        self,
    ) -> None:
        duplicate = self.run_dir / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        duplicate_out = self.run_dir / "duplicate-out.json"
        duplicate_process, duplicate_result = self.run_cli_path(
            duplicate,
            duplicate_out,
        )
        self.assertEqual(duplicate_process.returncode, 1)
        self.assertEqual(
            duplicate_result["error"]["code"],
            "json_duplicate_key",
        )
        self.assertNotIn("Traceback", duplicate_process.stderr)

        source = self.run_dir / "source.json"
        source.write_text(
            json.dumps(request_payload(), ensure_ascii=False),
            encoding="utf-8",
        )
        symlink = self.run_dir / "request-link.json"
        symlink.symlink_to(source)
        symlink_out = self.run_dir / "symlink-out.json"
        symlink_process, symlink_result = self.run_cli_path(
            symlink,
            symlink_out,
        )
        self.assertEqual(symlink_process.returncode, 1)
        self.assertEqual(
            symlink_result["error"]["code"],
            "request_symlink_rejected",
        )
        self.assertNotIn("Traceback", symlink_process.stderr)

        large = self.run_dir / "large.json"
        large.write_bytes(b" " * 1_048_577)
        large_out = self.run_dir / "large-out.json"
        large_process, large_result = self.run_cli_path(
            large,
            large_out,
        )
        self.assertEqual(large_process.returncode, 1)
        self.assertEqual(
            large_result["error"]["code"],
            "request_too_large",
        )
        self.assertNotIn("Traceback", large_process.stderr)

    @unittest.skipUnless(hasattr(os, "link"), "hard links unsupported")
    def test_cli_rejects_hardlinked_request(self) -> None:
        source = self.run_dir / "source.json"
        source.write_text(
            json.dumps(request_payload(), ensure_ascii=False),
            encoding="utf-8",
        )
        hardlink = self.run_dir / "request-hardlink.json"
        os.link(source, hardlink)
        output = self.run_dir / "hardlink-out.json"

        process, result = self.run_cli_path(hardlink, output)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            result["error"]["code"],
            "request_hardlink_rejected",
        )
        self.assertTrue(result["not_authorization"])
        self.assertNotIn("Traceback", process.stderr)

    def test_reader_rejects_in_place_mutation_during_read(self) -> None:
        request = self.run_dir / "mutable.json"
        request.write_text(
            json.dumps(request_payload(), ensure_ascii=False),
            encoding="utf-8",
        )
        original_read = os.read
        mutated = False

        def read_then_mutate(descriptor: int, count: int) -> bytes:
            nonlocal mutated
            chunk = original_read(descriptor, count)
            if chunk and not mutated:
                with request.open("ab") as handle:
                    handle.write(b" ")
                    handle.flush()
                    os.fsync(handle.fileno())
                mutated = True
            return chunk

        with (
            mock.patch.object(
                qa_common.os,
                "read",
                side_effect=read_then_mutate,
            ),
            self.assertRaises(CriticContractError) as caught,
        ):
            critic_cli._read_object(request)

        self.assertTrue(mutated)
        self.assertEqual(caught.exception.code, "request_changed")


if __name__ == "__main__":
    unittest.main()
