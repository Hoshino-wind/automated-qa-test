---
name: automated-qa-test
description: Strict automated QA testing workflow for web/app features from a user-written requirement, GitHub issue/PR, bug report, or acceptance criteria. Use when Codex needs to dynamically derive a test plan, verify feature logic, interaction behavior, data/API flow, console/network errors, screenshots, no-fabrication evidence integrity, completeness checks, and produce an evidence-backed test report. Triggers include 自动化测试, 自动化qa-test, QA test, 测试需求, issue 测试, PR 测试, 功能逻辑测试, 交互测试, 数据是否通, 接口是否通, 错误检查, 严格测试, 不能有遗漏, 禁止编造数据, Playwright 测试报告.
---

# 自动化 QA-Test

Use this skill as a dynamic QA harness. Do not hardcode product pages, route lists, business rules, or expected results inside the skill. Derive them each time from the current request, issue, PR, requirement text, repo behavior, and visible runtime evidence.

## Core Principle

Treat every run as a fresh requirement audit:

1. Read the requirement source.
2. Extract expected behavior, actors, state changes, data dependencies, permissions, edge cases, and success/failure states.
3. Turn those into a test charter and executable test plan.
4. Test feature logic, interaction quality, data/API continuity, and runtime errors.
5. Report what was covered, what passed, what failed, and what remains unverified.

## Evidence Integrity Contract

Be strict. Do not optimize for a nice-looking report; optimize for truth.

- Do not fabricate requirements, data, results, screenshots, response bodies, logs, timings, defect counts, or coverage percentages.
- Do not mark a requirement as passed unless the run produced direct evidence for that requirement.
- Do not infer backend/data correctness from a successful UI render alone. Verify API, persistence, logs, or returned data when the requirement depends on data flow.
- Do not hide untested areas. If something was not tested, mark it `Untested`. If it could not be tested, mark it `Blocked` and state the blocker.
- Do not collapse multiple requirement points into one generic pass. Each explicit acceptance criterion needs its own status.
- Do not treat mock/demo data as real data unless the requirement explicitly accepts mock data.
- Do not use stale screenshots, old report data, or previous-run results as current evidence unless the report labels them as historical context.
- If evidence is ambiguous, write `Inconclusive`, explain why, and name the exact evidence still needed.

Allowed statuses:

- `Passed`: directly verified with evidence.
- `Failed`: tested and contradicted expected behavior.
- `Blocked`: could not be tested because of a concrete blocker.
- `Untested`: not reached within the run scope.
- `Inconclusive`: evidence exists but is insufficient or contradictory.

## Requirement Intake

When the user provides an issue, PR, URL, screenshot, or free-form requirement:

- Gather the latest requirement text from the provided source. If the source is a GitHub issue/PR, inspect the description, comments that change scope, linked commits if relevant, and changed files when useful.
- If the user writes the requirement directly, use that text as the source of truth.
- If the current browser page is relevant, inspect the visible UI and network behavior before deciding the test surface.
- Do not ask for clarification unless a destructive action, production mutation, or missing access blocks meaningful testing.

Extract these fields into a working test charter:

- User goal: what outcome the feature should produce.
- Actors and permissions: who can do it and who should not.
- Entry points: pages, buttons, commands, API endpoints, scheduled jobs, or background flows.
- Data flow: required input, API calls, persistence, derived data, displayed data, and downstream effects.
- Logic rules: validation, branching, ordering, state transitions, authorization, retries, idempotency.
- Interaction rules: loading, disabled states, modal behavior, keyboard/mouse basics, responsive behavior, toasts, empty/error states.
- Acceptance criteria: explicit criteria from the requirement plus implicit criteria needed for the feature to work end to end.
- Risks and unknowns: parts that cannot be safely verified yet.

Use `references/test-charter.md` when a structured charter template is needed.

Completeness rule: after extraction, compare the test matrix back to the original requirement source line by line or paragraph by paragraph. Any requirement source line that implies behavior, data, permission, or interaction must map to at least one test item or to a documented `Out of scope`, `Blocked`, or `Untested` note.

## Planning

Create a dynamic test matrix before running broad tests. Prefer a compact table with:

- Requirement point
- Test type: logic, interaction, data/API, permission, error, regression, responsive
- Steps or probe
- Expected result
- Evidence to capture
- Status

For repeatable browser checks, create a JSON plan compatible with `scripts/playwright_probe.mjs`. Read `references/plan-schema.md` before authoring or editing the plan.

Do not include stale page lists just because a previous run used them. Add a route, API, or interaction only when the current requirement or discovered dependency justifies it.

Before execution, perform a coverage check:

- Every explicit requirement has at least one planned test.
- Every important data dependency has an API/log/persistence verification method or a documented blocker.
- Every create/update/delete flow has a safe test-data strategy.
- Every user-visible workflow has an interaction check for loading, disabled, validation, success, and error states when applicable.
- Every planned assertion names the evidence that will prove or disprove it.

## Execution

Use the lightest reliable evidence for each claim:

- Browser/UI: Playwright, in-app browser, or Chrome when login state is required.
- API/data flow: direct HTTP probes, application logs, database reads, or existing project test helpers.
- Logic: combine UI behavior with API/state evidence rather than relying on visual checks alone.
- Interaction: verify click targets, form validation, loading/disabled states, modal lifecycle, navigation, toasts, empty states, and responsive breakpoints.
- Errors: capture console errors, failed requests, HTTP 4xx/5xx, unhandled exceptions, traceback/log snippets, and user-visible error states.

Default artifact layout:

```text
<out-dir>/<timestamp>-<slug>/
├── requirement.md
├── test-charter.md
├── test-matrix.json
├── test-plan.json
├── results.json
├── evidence-ledger.json
├── audit-summary.json
├── screenshots/
└── report.md
```

Helpful scripts:

- `scripts/init_qa_artifact.py`: create a run folder and seed requirement, charter, and plan files.
- `scripts/playwright_probe.mjs`: execute a JSON browser test plan and collect screenshots, console errors, failed responses, and step results.
- `scripts/audit_evidence.py`: validate requirement coverage, statuses, and evidence references before final reporting.
- `scripts/generate_report.py`: convert a plan and results JSON into a Markdown QA report.

Scripts are helpers, not a substitute for judgment. Patch or extend the generated plan for the requirement under test before running it.

After execution, perform a second coverage check against the original matrix. Do not finish with a report that only lists automated steps if the requirement includes untested logic, data, permission, or interaction points. Add a coverage-gap section instead.

Before final reporting, update `evidence-ledger.json` and run:

```bash
python3 scripts/audit_evidence.py --matrix <run-dir>/test-matrix.json --ledger <run-dir>/evidence-ledger.json --summary <run-dir>/audit-summary.json
```

If the audit fails, do not claim the run passed. Fix the ledger, collect missing evidence, or mark items `Failed`, `Blocked`, `Untested`, or `Inconclusive` with notes.

## Severity

Classify defects by user impact:

- P0: blocks a primary requirement or corrupts/loses data.
- P1: breaks an important path, permission rule, or data/API continuity.
- P2: causes incorrect interaction, misleading state, missing validation, layout blocking, or recoverable API/UI error.
- P3: copy, polish, minor responsive issue, or low-risk inconsistency.

Every finding should include:

- Requirement or behavior affected
- Steps to reproduce
- Expected result
- Actual result
- Evidence: screenshot, log, request URL/status, response summary, or file reference
- Severity and confidence

For each finding, quote only observed facts. Separate interpretation from evidence with phrases like `Observed evidence` and `Inference`.

## Reporting

A good final report includes:

- Scope and requirement source
- Environment: branch, commit, URL, account role when relevant, services tested
- Evidence integrity statement: no fabricated data, no unstated assumptions, current-run evidence only unless labeled otherwise
- Evidence audit summary from `audit-summary.json`
- Test matrix with pass/fail/blocked status
- Defect list ordered by severity
- Console/network/API error summary
- Data-flow verification notes
- Interaction and responsive notes
- Coverage gaps and untested assumptions
- Screenshot evidence

Every report must include a `Coverage Gaps` section, even when it says `None identified in the tested scope`. This prevents silent omission.

If the user asks for a Feishu/Word/Google Docs report with screenshots, embed images in the document artifact before uploading/importing. Do not rely on local image paths inside the report text.

Use `references/report-template.md` when formatting a final report.

## Safety Rules

- Do not mutate production data unless the user explicitly authorizes that exact destination and action.
- Prefer test data or clearly reversible actions for create/update/delete flows.
- If testing requires sending personal data or inviting external users, confirm first.
- Keep unrelated repo changes out of QA runs unless the user requests fixes.
