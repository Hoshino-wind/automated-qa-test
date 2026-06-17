#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Any


LIST_MARKER_RE = re.compile(r"^(#{1,6}\s+|[-*+]\s+|\d+[\.)]\s+|- \[[ xX]\]\s+)")
LEADING_MARKER_RE = re.compile(r"^(#{1,6}\s+|[-*+]\s+|\d+[\.)]\s+|- \[[ xX]\]\s+)")
TOKEN_RE = re.compile(r"[A-Za-z0-9_:/.-]+|[\u4e00-\u9fff]")
IGNORE_LINE_RE = re.compile(r"^(背景|说明|备注|note|notes|context|background|scope|目标|目的)[:：]?$", re.IGNORECASE)


def try_read_text(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, f"read_error: {exc}"


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def clean_line(value: str) -> str:
    text = value.strip()
    text = LEADING_MARKER_RE.sub("", text).strip()
    text = re.sub(r"\s+", " ", text)
    return text


def normalize(value: str) -> str:
    text = clean_line(value).lower()
    text = re.sub(r"[`*_#>\[\](),，。；;！!？?\"'“”‘’]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def tokens(value: str) -> set[str]:
    return {item.lower() for item in TOKEN_RE.findall(normalize(value)) if item.strip()}


def split_sentences(text: str) -> list[str]:
    pieces = re.split(r"(?<=[。！？.!?])\s+|\n{2,}", text.strip())
    return [clean_line(piece) for piece in pieces if clean_line(piece)]


def source_units(requirement_text: str, max_units: int) -> list[dict[str, Any]]:
    raw_lines = requirement_text.splitlines()
    explicit: list[dict[str, Any]] = []
    for line_no, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cleaned = clean_line(stripped)
        if not cleaned or IGNORE_LINE_RE.match(cleaned):
            continue
        if LIST_MARKER_RE.match(stripped):
            explicit.append({"id": f"S{len(explicit) + 1}", "source": f"line {line_no}", "text": cleaned})
    if explicit:
        return explicit[:max_units]

    units: list[dict[str, Any]] = []
    for idx, piece in enumerate(split_sentences(requirement_text), 1):
        if IGNORE_LINE_RE.match(piece):
            continue
        units.append({"id": f"S{len(units) + 1}", "source": f"paragraph {idx}", "text": piece})
        if len(units) >= max_units:
            break
    if not units and requirement_text.strip():
        units.append({"id": "S1", "source": "requirement", "text": clean_line(requirement_text)})
    return units


def matrix_requirements(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in as_list(matrix.get("requirements")):
        if not isinstance(item, dict):
            continue
        out.append(item)
    return out


def coverage_match(unit: dict[str, Any], requirement: dict[str, Any], min_overlap: float) -> dict[str, Any] | None:
    unit_text = normalize(unit.get("text", ""))
    req_text = normalize(str(requirement.get("text") or ""))
    req_source = normalize(str(requirement.get("source") or ""))
    unit_source = normalize(str(unit.get("source") or ""))
    if unit_source and unit_source in req_source:
        return {"method": "source", "score": 1.0}
    if unit_text and req_text and (unit_text in req_text or req_text in unit_text):
        return {"method": "text_contains", "score": 1.0}
    unit_tokens = tokens(unit_text)
    req_tokens = tokens(req_text + " " + req_source)
    if not unit_tokens or not req_tokens:
        return None
    overlap = len(unit_tokens.intersection(req_tokens)) / max(len(unit_tokens), 1)
    if overlap >= min_overlap:
        return {"method": "token_overlap", "score": round(overlap, 3)}
    return None


def audit(requirement_text: str, matrix: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    units = source_units(requirement_text, args.max_units)
    requirements = matrix_requirements(matrix)
    coverage: list[dict[str, Any]] = []
    uncovered: list[dict[str, Any]] = []
    for unit in units:
        matches: list[dict[str, Any]] = []
        for req in requirements:
            match = coverage_match(unit, req, args.min_overlap)
            if match:
                matches.append({
                    "requirement_id": req.get("id"),
                    "requirement_status": req.get("status"),
                    "method": match["method"],
                    "score": match["score"],
                })
        covered = bool(matches)
        item = {
            **unit,
            "covered": covered,
            "matches": matches,
        }
        coverage.append(item)
        if not covered:
            uncovered.append(item)

    errors = [
        f"{item['id']} ({item['source']}) is not mapped to any matrix requirement: {item['text']}"
        for item in uncovered
    ]
    if not requirements:
        errors.append("test-matrix.json has no requirements to cover the requirement source.")

    return {
        "schema_version": 1,
        "requirement_unit_count": len(units),
        "matrix_requirement_count": len(requirements),
        "covered_count": len([item for item in coverage if item.get("covered")]),
        "uncovered_count": len(uncovered),
        "passed": not errors or args.allow_unmapped_source,
        "coverage": coverage,
        "errors": [] if args.allow_unmapped_source else errors,
        "warnings": errors if args.allow_unmapped_source else [],
        "input_artifact_errors": [],
    }


def input_error_summary(
    requirement_path: Path,
    matrix_path: Path,
    requirement_text: str | None,
    matrix: dict[str, Any] | None,
    input_errors: list[dict[str, str]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    units = source_units(requirement_text, args.max_units) if requirement_text is not None else []
    requirements = matrix_requirements(matrix or {})
    coverage = [{**unit, "covered": False, "matches": []} for unit in units]
    errors = [
        f"{item['name']} artifact is unreadable: {item['error']} ({item['path']})"
        for item in input_errors
    ]
    return {
        "schema_version": 1,
        "requirement": str(requirement_path),
        "matrix": str(matrix_path),
        "requirement_unit_count": len(units),
        "matrix_requirement_count": len(requirements),
        "covered_count": 0,
        "uncovered_count": len(units),
        "passed": False,
        "coverage": coverage,
        "errors": errors,
        "warnings": [],
        "input_artifact_errors": input_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit whether requirement.md source behavior points are represented in test-matrix.json.")
    parser.add_argument("--requirement", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out")
    parser.add_argument("--min-overlap", type=float, default=0.72)
    parser.add_argument("--max-units", type=int, default=80)
    parser.add_argument("--allow-unmapped-source", action="store_true", help="Write warnings instead of failing for uncovered requirement source units.")
    args = parser.parse_args()

    requirement_path = Path(args.requirement).expanduser().resolve()
    matrix_path = Path(args.matrix).expanduser().resolve()
    requirement_text, requirement_error = try_read_text(requirement_path)
    matrix, matrix_error = try_load_json(matrix_path)
    input_errors: list[dict[str, str]] = []
    if requirement_error:
        input_errors.append({"name": "requirement", "path": str(requirement_path), "error": requirement_error})
    if matrix_error:
        input_errors.append({"name": "matrix", "path": str(matrix_path), "error": matrix_error})

    if input_errors:
        summary = input_error_summary(requirement_path, matrix_path, requirement_text, matrix, input_errors, args)
    else:
        assert requirement_text is not None
        assert matrix is not None
        summary = audit(requirement_text, matrix, args)
        summary["requirement"] = str(requirement_path)
        summary["matrix"] = str(matrix_path)
    if args.out:
        write_json(Path(args.out).expanduser().resolve(), summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
