#!/usr/bin/env python3
import argparse
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path


def slugify(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "-", text.strip().lower()).strip("-")
    return value[:48] or "requirement-qa"


def load_requirement(args: argparse.Namespace) -> str:
    parts = []
    if args.requirement_file:
        parts.append(Path(args.requirement_file).read_text(encoding="utf-8"))
    if args.requirement_text:
        parts.append(args.requirement_text)
    return "\n\n".join(p.strip() for p in parts if p.strip())


def seed_plan(base_url: str, artifact_dir: Path) -> dict:
    return {
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "viewport": {"width": 1440, "height": 980},
        "headless": True,
        "scenarios": [
            {
                "id": "seed-smoke",
                "title": "Seed smoke scenario - replace with requirement-specific steps",
                "steps": [
                    {"action": "goto", "path": "/"},
                    {"action": "screenshot", "name": "seed-home"},
                ],
            }
        ],
    }


def seed_matrix() -> dict:
    return {
        "requirements": [
            {
                "id": "R1",
                "source": "requirement.md",
                "text": "TODO: replace with an exact requirement point from the source.",
                "risk": "TBD",
                "test_ids": ["T1"],
                "status": "Pending",
            }
        ],
        "tests": [
            {
                "id": "T1",
                "requirement_ids": ["R1"],
                "type": "smoke",
                "steps": ["Open the entry point and capture a screenshot."],
                "expected": "The page renders without runtime errors.",
                "required_evidence": ["screenshot", "console/network summary"],
                "status": "Pending",
            }
        ],
    }


def seed_ledger() -> dict:
    return {
        "requirements": [
            {
                "id": "R1",
                "source": "requirement.md",
                "text": "TODO: replace with an exact requirement point from the source.",
                "test_ids": ["T1"],
                "status": "Untested",
                "evidence_ids": [],
                "notes": "Seed entry. Replace before final reporting.",
            }
        ],
        "tests": [
            {
                "id": "T1",
                "requirement_ids": ["R1"],
                "type": "smoke",
                "expected": "The page renders without runtime errors.",
                "status": "Untested",
                "evidence_ids": [],
                "notes": "Seed entry. Replace with executed test result before final reporting.",
            }
        ],
        "evidence": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a requirement-driven QA artifact folder.")
    parser.add_argument("--requirement-file", help="Path to requirement, issue, or PR notes.")
    parser.add_argument("--requirement-text", help="Inline requirement text.")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--out-dir", default=str(Path(tempfile.gettempdir()) / "requirement-driven-qa"))
    parser.add_argument("--slug", help="Readable run slug.")
    args = parser.parse_args()

    requirement = load_requirement(args)
    title_seed = args.slug or (requirement.splitlines()[0] if requirement else "requirement qa")
    run_id = f"{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}-{slugify(title_seed)}"
    run_dir = Path(args.out_dir).expanduser() / run_id
    screenshots = run_dir / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)

    (run_dir / "requirement.md").write_text(requirement or "# Requirement\n\nTODO: paste requirement text here.\n", encoding="utf-8")
    (run_dir / "test-charter.md").write_text(
        "# Test Charter\n\n"
        "## Requirement Extraction\n\n"
        "| ID | Requirement Point | Source Evidence | Test Mapping | Status |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| R1 | TODO | requirement.md | T1 | Untested |\n\n"
        "Do not leave a requirement point unmapped. If it is out of scope, blocked, or unsafe to test, state that explicitly in `Test Mapping`.\n\n"
        "## Test Matrix\n\n"
        "| ID | Requirement | Test Type | Steps/Probe | Expected Result | Required Evidence | Actual Evidence | Status |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        "| T1 | R1 | smoke | Open entry point | Page renders without runtime errors | screenshot/network |  | Untested |\n\n"
        "Allowed statuses: Passed, Failed, Blocked, Untested, Inconclusive.\n\n"
        "## Coverage Gaps\n\n"
        "- Blocked:\n"
        "- Not safe to test:\n"
        "- Needs user-provided credential/data:\n"
        "- Deferred regression scope:\n"
        "- Requirement points without evidence:\n",
        encoding="utf-8",
    )
    plan = seed_plan(args.base_url, run_dir)
    (run_dir / "test-plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "test-matrix.json").write_text(json.dumps(seed_matrix(), indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "evidence-ledger.json").write_text(json.dumps(seed_ledger(), indent=2, ensure_ascii=False), encoding="utf-8")

    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
