# 自动化 QA-Test

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Codex skill for strict, requirement-driven QA of web applications and APIs.

This skill helps Codex turn a requirement, issue, PR, or bug report into a test matrix, execute browser/API probes, maintain an evidence ledger, audit the evidence, and generate a report without fabricating data.

## Skill Name

```text
$automated-qa-test
```

## What It Does

- Extracts requirement points from user text, issues, PRs, or acceptance criteria.
- Builds a dynamic test matrix instead of relying on hardcoded routes or stale page lists.
- Runs Playwright-based browser/API probes through a reusable JSON plan.
- Tracks requirement, test, and evidence mappings in `evidence-ledger.json`.
- Fails audit checks when a requirement is marked `Passed` without evidence.
- Forces unverified work into `Blocked`, `Untested`, or `Inconclusive` instead of guessing.

## Install

Copy the skill folder into your Codex skills directory:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/automated-qa-test "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Restart Codex if the skill list does not refresh automatically.

Or install from this repository with your preferred Codex skill installer if available:

```bash
python3 "${CODEX_HOME:-$HOME/.codex}/skills/.system/skill-installer/scripts/install-skill-from-github.py" \
  --repo Hoshino-wind/automated-qa-test \
  --path skills/automated-qa-test
```

## Usage

Ask Codex to use the skill with a requirement, issue, PR, or test scope:

```text
Use $automated-qa-test to strictly test this requirement. Do not fabricate data. Every Passed item must have evidence.
```

Example requirement:

```text
Use $automated-qa-test to test this issue end to end.
Requirements:
- The user can submit the form.
- The API returns 200.
- The created record appears in the list.
- Do not fabricate data.
- Mark anything without direct evidence as Untested, Blocked, or Inconclusive.
```

Typical workflow:

1. Create a run artifact folder.
2. Convert the requirement into `test-matrix.json`.
3. Create or refine `test-plan.json`.
4. Run the Playwright probe.
5. Fill `evidence-ledger.json` from current-run evidence.
6. Run the evidence audit.
7. Generate the report.

## Helper Scripts

From the skill directory:

```bash
python3 scripts/init_qa_artifact.py \
  --requirement-text "User can submit the form and see the saved item in the list." \
  --base-url http://127.0.0.1:3000
```

```bash
node scripts/playwright_probe.mjs --plan /path/to/run/test-plan.json
```

```bash
python3 scripts/audit_evidence.py \
  --matrix /path/to/run/test-matrix.json \
  --ledger /path/to/run/evidence-ledger.json \
  --summary /path/to/run/audit-summary.json
```

```bash
python3 scripts/generate_report.py \
  --plan /path/to/run/test-plan.json \
  --results /path/to/run/results.json \
  --requirement /path/to/run/requirement.md \
  --ledger /path/to/run/evidence-ledger.json \
  --audit-summary /path/to/run/audit-summary.json \
  --out /path/to/run/report.md
```

## Evidence Rules

Allowed requirement statuses:

- `Passed`
- `Failed`
- `Blocked`
- `Untested`
- `Inconclusive`

`Passed` requires direct current-run evidence. UI rendering alone does not prove data/API correctness when the requirement depends on data flow.

The audit fails when:

- a requirement has no mapped tests;
- a matrix requirement or test is missing from the evidence ledger;
- a `Passed` requirement has no evidence;
- a `Passed` test has no evidence;
- a requirement or test references missing evidence;
- screenshot/file evidence points to a missing local file;
- a non-passed item lacks explanatory notes.

## Privacy

Do not commit run artifacts that contain screenshots, logs, reports, credentials, tokens, session data, customer data, or private URLs. The repository `.gitignore` excludes common generated QA artifacts by default.

## License

MIT
