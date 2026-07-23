#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json

SAFE_REQUIRED_INPUTS = {
    "current-run execution evidence",
    "baseUrl",
    "failed API path",
    "target selector or role/name",
    "only add ignorePatterns for known benign, documented runtime noise",
}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PLACEHOLDER_RE = re.compile(r"<[^>]+>")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def try_load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid_json: {exc.msg}"
    except OSError as exc:
        return None, f"read_error: {exc}"
    if not isinstance(value, dict):
        return None, "json_root_not_object"
    return value, None


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_json(path, value)


def file_sha256(path: Path) -> str | None:
    if not path.exists() or path.is_dir():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def resolve_artifact_path(run_dir: Path, value: Any) -> Path | None:
    if not has_text(value):
        return None
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = run_dir / path
    return path.resolve()


def generated_from_errors(next_probes: dict[str, Any], run_dir: Path, expected_paths: dict[str, Path]) -> list[dict[str, Any]]:
    generated = next_probes.get("generated_from")
    if not isinstance(generated, dict):
        return [{
            "name": "next_probes.generated_from",
            "path": "",
            "error": "missing_current_run_source_binding",
            "required": True,
        }]
    source_hashes = next_probes.get("generated_from_hashes")
    errors: list[dict[str, Any]] = []
    if not isinstance(source_hashes, dict):
        errors.append({
            "name": "next_probes.generated_from_hashes",
            "path": "",
            "error": "missing_source_hashes",
            "required": True,
        })
        source_hashes = {}
    for key, expected in expected_paths.items():
        source = generated.get(key)
        if source is None:
            if key == "defects":
                errors.append({
                    "name": f"next_probes.generated_from.{key}",
                    "path": "",
                    "error": "missing_required_source",
                    "required": True,
                })
            continue
        resolved = resolve_artifact_path(run_dir, source)
        if resolved is None:
            continue
        expected_resolved = expected.resolve()
        if resolved != expected_resolved:
            errors.append({
                "name": f"next_probes.generated_from.{key}",
                "path": str(resolved),
                "error": f"source_mismatch: expected {expected_resolved}",
                "required": True,
            })
            continue
        hash_key = f"{key}_sha256"
        expected_hash = source_hashes.get(hash_key)
        if not has_text(expected_hash):
            errors.append({
                "name": f"next_probes.generated_from_hashes.{key}",
                "path": str(expected_resolved),
                "error": "missing_source_hash",
                "required": True,
            })
            continue
        current_hash = file_sha256(expected_resolved)
        if current_hash is None:
            errors.append({
                "name": f"next_probes.generated_from_hashes.{key}",
                "path": str(expected_resolved),
                "error": "source_unreadable_for_hash",
                "required": True,
            })
        elif current_hash != str(expected_hash):
            errors.append({
                "name": f"next_probes.generated_from_hashes.{key}",
                "path": str(expected_resolved),
                "error": f"source_hash_mismatch: expected {expected_hash}",
                "required": True,
            })
    return errors


def embedded_input_artifact_errors(next_probes: dict[str, Any], next_path: Path) -> list[dict[str, Any]]:
    raw_errors = next_probes.get("input_artifact_errors")
    errors: list[dict[str, Any]] = []
    if isinstance(raw_errors, list):
        for index, item in enumerate(raw_errors):
            if isinstance(item, dict):
                name = str(item.get("name") or f"item_{index}")
                path = str(item.get("path") or next_path)
                error = str(item.get("error") or "input_artifact_error")
                errors.append({
                    "name": f"next_probes.{name}",
                    "path": path,
                    "error": error,
                    "required": True,
                })
            else:
                errors.append({
                    "name": f"next_probes.input_artifact_errors[{index}]",
                    "path": str(next_path),
                    "error": "entry_not_object",
                    "required": True,
                })
    summary = next_probes.get("summary") if isinstance(next_probes.get("summary"), dict) else {}
    try:
        declared_count = int(summary.get("input_artifact_error_count") or 0)
    except (TypeError, ValueError):
        declared_count = 0
    if declared_count > 0 and not errors:
        errors.append({
            "name": "next_probes.input_artifact_errors",
            "path": str(next_path),
            "error": "declared_input_artifact_errors_missing",
            "required": True,
        })
    return errors


def slug(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip()).strip("-").lower()
    return text[:64] or "probe"


def walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(walk_strings(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(walk_strings(item))
        return out
    return []


def contains_placeholder(value: Any) -> bool:
    strings = walk_strings(value)
    if any(PLACEHOLDER_RE.search(text) for text in strings):
        return True
    placeholder_phrases = (
        "provide project-approved",
        "add focused requirement probe",
        "add project-specific probe",
        "echo provide",
    )
    return any(any(phrase in text.lower() for phrase in placeholder_phrases) for text in strings)


def infer_evidence_type(action: str) -> str:
    return {
        "goto": "navigation",
        "api": "api_response",
        "cleanupApi": "cleanup",
        "clickAndWaitForResponse": "ui_to_api",
        "websocket": "websocket",
        "sse": "sse",
        "command": "command",
        "screenshot": "screenshot",
        "expectVisible": "ui_assertion",
        "expectNoConsoleErrors": "runtime",
        "expectNoFailedResponses": "runtime",
        "expectNoRequestFailures": "runtime",
    }.get(action, "probe_step")


def plan_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for scenario in as_list(plan.get("scenarios")):
        out.extend(as_list(scenario.get("steps")))
    return out


def ensure_scenario(plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan.get("scenarios"), list):
        plan["scenarios"] = []
    for scenario in plan["scenarios"]:
        if scenario.get("id") == "next-probe-followups":
            return scenario
    scenario = {
        "id": "next-probe-followups",
        "title": "Applied next-probe follow-ups",
        "continueOnFailure": True,
        "steps": [],
    }
    plan["scenarios"].append(scenario)
    return scenario


def list_value(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if has_text(item)]


def test_lookup(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in as_list(matrix.get("tests")) if has_text(item.get("id"))}


def req_lookup(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in as_list(matrix.get("requirements")) if has_text(item.get("id"))}


def defect_lookup(defects: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in as_list((defects or {}).get("findings")) if has_text(item.get("id"))}


def evidence_lookup(ledger: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in as_list((ledger or {}).get("evidence")) if has_text(item.get("id"))}


def ids_from_recommendation(
    rec: dict[str, Any],
    matrix: dict[str, Any],
    ledger: dict[str, Any] | None,
    defects: dict[str, Any] | None,
) -> tuple[list[str], list[str]]:
    tests_by_id = test_lookup(matrix)
    defects_by_id = defect_lookup(defects)
    evidence_by_id = evidence_lookup(ledger)
    test_ids: list[str] = []
    req_ids: list[str] = []

    if has_text(rec.get("source_test_id")):
        test_ids.append(str(rec["source_test_id"]))
    test_ids.extend(list_value(rec.get("source_test_ids")))
    req_ids.extend(list_value(rec.get("requirement_ids")))

    finding = defects_by_id.get(str(rec.get("finding_id") or ""))
    if finding:
        test_ids.extend(list_value(finding.get("affected_tests")))
        for item in as_list(finding.get("affected_requirements")):
            if isinstance(item, dict) and has_text(item.get("id")):
                req_ids.append(str(item["id"]))

    for evidence_id in list_value(rec.get("evidence_ids")):
        evidence = evidence_by_id.get(evidence_id)
        if not evidence:
            continue
        test_ids.extend(list_value(evidence.get("test_ids")))
        req_ids.extend(list_value(evidence.get("requirement_ids")))

    for test_id in list(dict.fromkeys(test_ids)):
        test = tests_by_id.get(test_id)
        if test:
            req_ids.extend(list_value(test.get("requirement_ids")))

    return list(dict.fromkeys(test_ids)), list(dict.fromkeys(req_ids))


def runtime_test_id(action: str) -> str:
    return {
        "expectNoConsoleErrors": "T-runtime-console-errors-disposition",
        "expectNoFailedResponses": "T-runtime-failed-responses-disposition",
        "expectNoRequestFailures": "T-runtime-request-failures-disposition",
    }.get(action, f"T-runtime-{slug(action)}")


def ensure_runtime_matrix_mapping(matrix: dict[str, Any], rec: dict[str, Any], hint: dict[str, Any]) -> tuple[list[str], list[str]]:
    action = str(hint.get("action") or "")
    req_id = "R-runtime-issue-disposition"
    test_id = runtime_test_id(action)
    if not isinstance(matrix.get("requirements"), list):
        matrix["requirements"] = []
    if not isinstance(matrix.get("tests"), list):
        matrix["tests"] = []

    reqs = req_lookup(matrix)
    if req_id not in reqs:
        matrix["requirements"].append({
            "id": req_id,
            "source": "runtime-results",
            "text": "Captured console errors, failed HTTP responses, and request failures must be explicitly dispositioned before a pass claim.",
            "test_ids": [test_id],
            "status": "Untested",
        })
    else:
        req = reqs[req_id]
        existing = list_value(req.get("test_ids"))
        if test_id not in existing:
            existing.append(test_id)
            req["test_ids"] = existing
        if req.get("status") == "Passed":
            req["status"] = "Untested"

    tests = test_lookup(matrix)
    if test_id not in tests:
        matrix["tests"].append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "runtime",
            "steps": [str(rec.get("objective") or "Disposition captured runtime issues.")],
            "expected": "No unignored runtime issue of this type remains in the current run, or the issue is mapped to a failed requirement.",
            "required_evidence": ["runtime disposition probe", "results.json runtime arrays"],
            "status": "Untested",
        })
    elif tests[test_id].get("status") == "Passed":
        tests[test_id]["status"] = "Untested"
    return [test_id], [req_id]


def equivalent_step_exists(existing_steps: list[dict[str, Any]], step: dict[str, Any]) -> bool:
    step_id = str(step.get("id") or "")
    if step_id and any(str(item.get("id") or item.get("stepId") or "") == step_id for item in existing_steps):
        return True
    action = step.get("action")
    path = json.dumps(step.get("path") or step.get("url") or step.get("selector") or step.get("text") or "", sort_keys=True, ensure_ascii=False)
    tests = set(list_value(step.get("testIds")))
    reqs = set(list_value(step.get("requirementIds")))
    for item in existing_steps:
        if item.get("action") != action:
            continue
        item_path = json.dumps(item.get("path") or item.get("url") or item.get("selector") or item.get("text") or "", sort_keys=True, ensure_ascii=False)
        if path != item_path:
            continue
        item_tests = set(list_value(item.get("testIds")))
        item_reqs = set(list_value(item.get("requirementIds")))
        if tests and item_tests and tests.intersection(item_tests):
            if adds_diagnostic_capture(item, step):
                continue
            return True
        if reqs and item_reqs and reqs.intersection(item_reqs):
            if adds_diagnostic_capture(item, step):
                continue
            return True
    return False


def adds_diagnostic_capture(existing: dict[str, Any], step: dict[str, Any]) -> bool:
    diagnostic_keys = (
        "captureBody",
        "captureResponseHeaders",
        "expectJson",
        "expectResponseTextContains",
        "expectResponseTextNotContains",
        "extractJson",
        "extractResponseHeader",
    )
    return any(bool(step.get(key)) and not bool(existing.get(key)) for key in diagnostic_keys)


def blocked_reason(rec: dict[str, Any], hint: dict[str, Any], args: argparse.Namespace) -> str | None:
    if not isinstance(hint, dict) or not hint:
        return "missing plan_step_hint"
    if contains_placeholder(hint):
        return "plan_step_hint contains a placeholder or project-specific stub"
    required_inputs = [str(item) for item in as_list(rec.get("required_inputs")) if has_text(item)]
    unknown_inputs = [item for item in required_inputs if item not in SAFE_REQUIRED_INPUTS]
    action = str(hint.get("action") or "").lower()
    if action in {"websocket", "sse"}:
        unknown_inputs = [item for item in unknown_inputs if item not in {"auth state", "safe payload", "--allow-live-stream when generated from scaffold"}]
        if not args.allow_live_stream:
            return "stream probe requires --allow-live-stream"
    if action == "command" and not args.allow_command_probes:
        return "command probe requires --allow-command-probes"
    if action == "api":
        method = str(hint.get("method") or "GET").upper()
        if method in MUTATING_METHODS and not args.allow_mutating_api:
            return f"mutating API method {method} requires --allow-mutating-api"
    if any("auth" in item.lower() or "token" in item.lower() or "account" in item.lower() for item in unknown_inputs):
        return "recommendation requires auth/account inputs that were not supplied"
    if unknown_inputs and not args.allow_required_input_gaps:
        return "required inputs not satisfied: " + ", ".join(unknown_inputs)
    return None


def build_step(rec: dict[str, Any], hint: dict[str, Any], test_ids: list[str], req_ids: list[str]) -> dict[str, Any]:
    step = copy.deepcopy(hint)
    rec_id = str(rec.get("id") or "NP")
    step.setdefault("id", f"next-{slug(rec_id)}")
    if test_ids:
        step["testIds"] = test_ids
    if req_ids:
        step["requirementIds"] = req_ids
    action = str(step.get("action") or "probe")
    step.setdefault("evidenceType", infer_evidence_type(action))
    objective = str(rec.get("objective") or "").strip()
    reason = str(rec.get("reason") or "").strip()
    proves = objective or reason or f"Next-probe recommendation {rec_id} produces current-run evidence."
    step.setdefault("proves", proves)
    return step


def recompute_requirements(matrix: dict[str, Any]) -> None:
    tests_by_req: dict[str, list[dict[str, Any]]] = {}
    for test in as_list(matrix.get("tests")):
        for req_id in list_value(test.get("requirement_ids")):
            tests_by_req.setdefault(req_id, []).append(test)
    for req in as_list(matrix.get("requirements")):
        related = tests_by_req.get(str(req.get("id")), [])
        statuses = [test.get("status") for test in related]
        if any(status == "Failed" for status in statuses):
            req["status"] = "Failed"
        elif any(status == "Untested" for status in statuses):
            req["status"] = "Untested"
            if str(req.get("notes", "")).startswith("Generated requirement has no executable"):
                req.pop("notes", None)
        elif related and all(status == "Passed" for status in statuses):
            req["status"] = "Passed"
        elif any(status == "Inconclusive" for status in statuses):
            req["status"] = "Inconclusive"
        elif any(status == "Blocked" for status in statuses):
            req["status"] = "Blocked"


def mark_tests_executable(matrix: dict[str, Any], test_ids: list[str]) -> None:
    ids = set(test_ids)
    for test in as_list(matrix.get("tests")):
        if str(test.get("id")) not in ids:
            continue
        if test.get("status") == "Blocked":
            test["status"] = "Untested"
            if str(test.get("notes", "")).startswith("Generated as a blocked probe"):
                test.pop("notes", None)
    recompute_requirements(matrix)


def apply_recommendations(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], int]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    plan_path = Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
    next_path = Path(args.next_probes).expanduser().resolve() if args.next_probes else run_dir / "next-probes.json"
    ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else run_dir / "evidence-ledger.json"
    defects_path = Path(args.defects).expanduser().resolve() if args.defects else run_dir / "defects.json"

    input_errors: list[dict[str, Any]] = []

    def load_required(name: str, path: Path) -> dict[str, Any]:
        value, load_error = try_load_json(path)
        if load_error:
            input_errors.append({"name": name, "path": str(path), "error": load_error, "required": True})
            return {}
        return value or {}

    def load_optional(name: str, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        value, load_error = try_load_json(path)
        if load_error:
            input_errors.append({"name": name, "path": str(path), "error": load_error, "required": False})
            return None
        return value

    plan = load_required("plan", plan_path)
    matrix = load_required("matrix", matrix_path)
    original_plan = copy.deepcopy(plan)
    original_matrix = copy.deepcopy(matrix)
    next_probes = load_required("next_probes", next_path)
    ledger = load_optional("ledger", ledger_path)
    defects = load_optional("defects", defects_path)
    if next_probes:
        input_errors.extend(embedded_input_artifact_errors(next_probes, next_path))
        input_errors.extend(generated_from_errors(
            next_probes,
            run_dir,
            {
                "defects": defects_path,
                "results": run_dir / "results.json",
                "ledger": ledger_path,
            },
        ))

    if input_errors:
        return {
            "schema_version": 1,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "applied": bool(args.apply),
            "plan": str(plan_path),
            "matrix": str(matrix_path),
            "next_probes": str(next_path),
            "input_artifact_errors": input_errors,
            "summary": {
                "recommendation_count": 0,
                "applied_count": 0,
                "skipped_count": 0,
                "skipped_reason_counts": {},
                "applied_layer_counts": {},
            },
            "applied_recommendations": [],
            "skipped_recommendations": [],
            "safety": {
                "stream_requires_allow_live_stream": True,
                "command_requires_allow_command_probes": True,
                "mutating_api_requires_allow_mutating_api": True,
                "placeholders_are_never_applied": True,
                "lineage_required_for_auto_apply": True,
                "current_run_source_binding_required": True,
                "current_run_source_hash_required": True,
            },
        }, original_plan, original_matrix, 1

    existing_steps = plan_steps(plan)
    scenario = ensure_scenario(plan)
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    proposed_steps: list[dict[str, Any]] = []

    for rec in as_list(next_probes.get("recommendations")):
        rec_id = str(rec.get("id") or f"rec-{len(applied) + len(skipped) + 1}")
        hint = rec.get("plan_step_hint") if isinstance(rec.get("plan_step_hint"), dict) else {}
        test_ids, req_ids = ids_from_recommendation(rec, matrix, ledger, defects)
        if not test_ids and not req_ids and rec.get("layer") == "runtime" and hint:
            test_ids, req_ids = ensure_runtime_matrix_mapping(matrix, rec, hint)
        step = build_step(rec, hint, test_ids, req_ids) if hint else {}
        reason = blocked_reason(rec, hint, args)
        if reason:
            skipped.append({"id": rec_id, "reason": reason, "layer": rec.get("layer"), "source_test_id": rec.get("source_test_id")})
            continue
        if not test_ids and not req_ids:
            skipped.append({"id": rec_id, "reason": "recommendation has no requirement/test lineage", "layer": rec.get("layer"), "source_test_id": rec.get("source_test_id")})
            continue
        if equivalent_step_exists(existing_steps, step):
            skipped.append({"id": rec_id, "reason": "equivalent step already exists in plan", "layer": rec.get("layer"), "source_test_id": rec.get("source_test_id")})
            continue
        proposed_steps.append(step)
        applied.append({
            "id": rec_id,
            "step_id": step.get("id"),
            "layer": rec.get("layer"),
            "test_ids": test_ids,
            "requirement_ids": req_ids,
        })
        if args.apply:
            scenario.setdefault("steps", []).append(step)
            existing_steps.append(step)
            mark_tests_executable(matrix, test_ids)

    skipped_counts = Counter(item["reason"] for item in skipped)
    layer_counts = Counter(item.get("layer") for item in applied)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "applied": bool(args.apply),
        "plan": str(plan_path),
        "matrix": str(matrix_path),
        "next_probes": str(next_path),
        "summary": {
            "recommendation_count": len(as_list(next_probes.get("recommendations"))),
            "applied_count": len(applied),
            "skipped_count": len(skipped),
            "skipped_reason_counts": dict(sorted(skipped_counts.items())),
            "applied_layer_counts": dict(sorted(layer_counts.items())),
        },
        "applied_recommendations": applied,
        "skipped_recommendations": skipped,
        "safety": {
            "stream_requires_allow_live_stream": True,
            "command_requires_allow_command_probes": True,
            "mutating_api_requires_allow_mutating_api": True,
            "placeholders_are_never_applied": True,
            "lineage_required_for_auto_apply": True,
            "current_run_source_binding_required": True,
            "current_run_source_hash_required": True,
        },
    }
    if not args.apply:
        report["plan_patch"] = {"scenario": "next-probe-followups", "steps": proposed_steps}
        plan = original_plan
        matrix = original_matrix
    return report, plan, matrix, 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply safe concrete next-probe recommendations back into a QA test plan.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--next-probes")
    parser.add_argument("--plan")
    parser.add_argument("--matrix")
    parser.add_argument("--ledger")
    parser.add_argument("--defects")
    parser.add_argument("--out")
    parser.add_argument("--apply", action="store_true", help="Write accepted next probes back to test-plan.json and test-matrix.json.")
    parser.add_argument("--plan-out", help="Defaults to --plan or <run-dir>/test-plan.json when --apply is set.")
    parser.add_argument("--matrix-out", help="Defaults to --matrix or <run-dir>/test-matrix.json when --apply is set.")
    parser.add_argument("--allow-live-stream", action="store_true")
    parser.add_argument("--allow-command-probes", action="store_true")
    parser.add_argument("--allow-mutating-api", action="store_true")
    parser.add_argument("--allow-required-input-gaps", action="store_true")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    report, plan, matrix, exit_code = apply_recommendations(args)
    out_path = Path(args.out).expanduser().resolve() if args.out else run_dir / "next-probe-application.json"
    write_json(out_path, report)
    if args.apply and exit_code == 0:
        plan_path = Path(args.plan_out).expanduser().resolve() if args.plan_out else Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
        matrix_path = Path(args.matrix_out).expanduser().resolve() if args.matrix_out else Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
        write_json(plan_path, plan)
        write_json(matrix_path, matrix)
    print(out_path)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
