#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Any


ALLOWED_STATUSES = {"Passed", "Failed", "Blocked", "Untested", "Inconclusive"}
PASSED = "Passed"
FILE_EVIDENCE_TYPES = {"screenshot", "file", "log_file", "trace", "video"}


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def resolve_evidence_path(base_dir: Path, raw_path: str) -> Path:
    p = Path(raw_path).expanduser()
    return p if p.is_absolute() else base_dir / p


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a requirement-driven QA evidence ledger.")
    parser.add_argument("--ledger", required=True, help="Path to evidence-ledger.json")
    parser.add_argument("--matrix", help="Optional test-matrix.json to verify ledger completeness.")
    parser.add_argument("--base-dir", help="Base directory for relative evidence paths. Defaults to ledger directory.")
    parser.add_argument("--summary", help="Optional path to write audit-summary.json")
    args = parser.parse_args()

    ledger_path = Path(args.ledger).expanduser().resolve()
    ledger = load_json(ledger_path)
    matrix = load_json(Path(args.matrix).expanduser().resolve()) if args.matrix else None
    base_dir = Path(args.base_dir).expanduser().resolve() if args.base_dir else ledger_path.parent

    requirements = as_list(ledger.get("requirements"))
    tests = as_list(ledger.get("tests"))
    evidence = as_list(ledger.get("evidence"))

    errors: list[str] = []
    warnings: list[str] = []

    if not requirements:
        errors.append("ledger.requirements is empty; cannot prove requirement coverage.")

    req_by_id = {}
    for req in requirements:
        req_id = req.get("id")
        if has_text(req_id):
            if req_id in req_by_id:
                errors.append(f"Duplicate requirement id: {req_id}")
            req_by_id[req_id] = req

    test_by_id = {}
    for item in tests:
        item_id = item.get("id")
        if not has_text(item_id):
            errors.append("A test entry is missing id.")
            continue
        if item_id in test_by_id:
            errors.append(f"Duplicate test id: {item_id}")
        test_by_id[item_id] = item

    evidence_by_id = {}
    for item in evidence:
        item_id = item.get("id")
        if not has_text(item_id):
            errors.append("An evidence entry is missing id.")
            continue
        if item_id in evidence_by_id:
            errors.append(f"Duplicate evidence id: {item_id}")
        evidence_by_id[item_id] = item

        if not has_text(item.get("proves")):
            errors.append(f"Evidence {item_id} is missing `proves` text.")

        evidence_type = item.get("type")
        raw_path = item.get("path") or item.get("file")
        if evidence_type in FILE_EVIDENCE_TYPES and has_text(raw_path):
            resolved = resolve_evidence_path(base_dir, raw_path)
            if not resolved.exists():
                errors.append(f"Evidence {item_id} points to missing file: {resolved}")

    for req in requirements:
        req_id = req.get("id")
        if not has_text(req_id):
            errors.append("A requirement entry is missing id.")
            continue
        if not has_text(req.get("source")):
            errors.append(f"Requirement {req_id} is missing source.")
        if not has_text(req.get("text")):
            errors.append(f"Requirement {req_id} is missing text.")

        status = req.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"Requirement {req_id} has invalid status: {status!r}")

        test_ids = [tid for tid in as_list(req.get("test_ids")) if has_text(tid)]
        if not test_ids:
            errors.append(f"Requirement {req_id} has no mapped tests.")
        for test_id in test_ids:
            if test_id not in test_by_id:
                errors.append(f"Requirement {req_id} references missing test {test_id}.")

        evidence_ids = [eid for eid in as_list(req.get("evidence_ids")) if has_text(eid)]
        if status == PASSED and not evidence_ids:
            errors.append(f"Requirement {req_id} is Passed without evidence.")
        if status != PASSED and not has_text(req.get("notes")):
            errors.append(f"Requirement {req_id} is {status} but has no explanatory notes.")
        for evidence_id in evidence_ids:
            if evidence_id not in evidence_by_id:
                errors.append(f"Requirement {req_id} references missing evidence {evidence_id}.")

    for test in tests:
        test_id = test.get("id")
        if not has_text(test_id):
            continue
        status = test.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"Test {test_id} has invalid status: {status!r}")
        requirement_ids = [rid for rid in as_list(test.get("requirement_ids")) if has_text(rid)]
        if not requirement_ids:
            errors.append(f"Test {test_id} maps to no requirements.")
        if not has_text(test.get("expected")):
            errors.append(f"Test {test_id} is missing expected behavior.")

        evidence_ids = [eid for eid in as_list(test.get("evidence_ids")) if has_text(eid)]
        if status == PASSED and not evidence_ids:
            errors.append(f"Test {test_id} is Passed without evidence.")
        if status != PASSED and not has_text(test.get("notes")):
            errors.append(f"Test {test_id} is {status} but has no explanatory notes.")
        for evidence_id in evidence_ids:
            if evidence_id not in evidence_by_id:
                errors.append(f"Test {test_id} references missing evidence {evidence_id}.")

    if matrix:
        matrix_req_ids = {item.get("id") for item in as_list(matrix.get("requirements")) if has_text(item.get("id"))}
        matrix_test_ids = {item.get("id") for item in as_list(matrix.get("tests")) if has_text(item.get("id"))}
        for req_id in sorted(matrix_req_ids):
            if req_id not in req_by_id:
                errors.append(f"Matrix requirement {req_id} is missing from evidence ledger.")
        for test_id in sorted(matrix_test_ids):
            if test_id not in test_by_id:
                errors.append(f"Matrix test {test_id} is missing from evidence ledger.")
        for req in as_list(matrix.get("requirements")):
            req_id = req.get("id")
            matrix_test_refs = {tid for tid in as_list(req.get("test_ids")) if has_text(tid)}
            ledger_test_refs = {tid for tid in as_list(req_by_id.get(req_id, {}).get("test_ids")) if has_text(tid)}
            missing_refs = matrix_test_refs - ledger_test_refs
            for test_id in sorted(missing_refs):
                errors.append(f"Ledger requirement {req_id} is missing matrix test mapping {test_id}.")

    total = len(requirements)
    counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    for req in requirements:
        status = req.get("status")
        if status in counts:
            counts[status] += 1

    summary = {
        "ledger": str(ledger_path),
        "matrix": str(Path(args.matrix).expanduser().resolve()) if args.matrix else None,
        "base_dir": str(base_dir),
        "requirement_count": total,
        "test_count": len(tests),
        "evidence_count": len(evidence),
        "status_counts": counts,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
    }

    if args.summary:
        Path(args.summary).expanduser().write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    if errors:
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
