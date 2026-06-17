---
name: automated-qa-test
description: Strict automated QA/backtest workflow for web/app features from a user-written requirement, GitHub issue/PR, bug report, or acceptance criteria. Use when Codex needs to dynamically derive a test plan, run UI/API/WebSocket/SSE/command probes, verify feature logic, interaction behavior, stream completion, persistence/data flow, console/network/runtime errors, screenshots, no-fabrication evidence integrity, completeness checks, and produce an evidence-backed test report. Triggers include 自动化测试, 自动化qa-test, QA test, 回测, 测试需求, issue 测试, PR 测试, 功能逻辑测试, 交互测试, 数据是否通, 接口是否通, WebSocket 流式, SSE 流式, 持久化验证, 错误检查, 严格测试, 不能有遗漏, 禁止编造数据, Playwright 测试报告.
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

## Agent Loop

Use this skill as an evidence-producing agent loop, not as a static checklist:

1. Compile the requirement into `business-model.json`, `oracle-model.json`, `test-charter.md`, `test-matrix.json`, `test-plan.json`, `qa-metrics.json`, and `closeout-candidates.json`. For a new free-form requirement, start with `scripts/init_qa_artifact.py` or `scripts/scaffold_requirement.py` so the first draft already maps business actors/entities/workflows to UI/API/stream/persistence probes or explicit blockers.
2. Select probes for each matrix row: UI, API, WebSocket/SSE, command/log/persistence, or manual blocker. When `adapter-context.json` exists, run `scripts/synthesize_adapter_probes.py` or `run_qa_cycle.py --synthesize-adapter-probes` before validation to convert known safe adapter paths into executable probes.
3. Run `scripts/preflight_runtime.py` or `run_qa_cycle.py --preflight-runtime` when local services, ports, or project tooling affect execution. Treat preflight blockers as run blockers, not test failures. If the target is a local/test checkout and the user wants the agent to bring services up, run `scripts/service_runtime.py --start` or `run_qa_cycle.py --start-missing-services` so startup PID/log/readiness evidence is captured in `service-runtime.json`.
4. Run `scripts/audit_requirement_coverage.py` or the default `run_qa_cycle.py` coverage gate when `requirement.md` exists. Every requirement-source behavior point must map to `test-matrix.json` before probes run.
5. Run `scripts/validate_plan.py` to catch unmapped matrix requirements, weak probe steps, TODO placeholders, secret-like values, and risky commands before execution.
6. Run `scripts/run_qa_cycle.py` for the full executable loop when using the bundled probe runner.
7. Apply safe concrete follow-up recommendations with `scripts/apply_next_probes.py` or `run_qa_cycle.py --apply-next-probes` before the next execution cycle.
8. Manually update `evidence-ledger.json` only when custom probes outside the runner were used.
9. Generate `qa-verdict.json` with `scripts/generate_verdict.py` or through `run_qa_cycle.py`. Treat `can_claim_pass=false` as the guardrail against calling a failed, blocked, untested, inconclusive, or unaudited run a pass.
10. Generate or write the report only from the audited ledger, verdict, and explicitly labeled gaps.

If the feature spans multiple services or has repo-specific data ownership rules, read `references/project-adapters.md` before planning probes.

When changing or interpreting `business-model.json`, `oracle-model.json`, `qa-metrics.json`, or `closeout-candidates.json`, read `references/business-oracle-model.md`.

## Evidence Integrity Contract

Be strict. Do not optimize for a nice-looking report; optimize for truth.

- Do not fabricate requirements, data, results, screenshots, response bodies, logs, timings, defect counts, or coverage percentages.
- Do not mark a requirement as passed unless the run produced direct evidence for that requirement.
- Do not mark a requirement as `Passed` while any mapped test remains `Failed`, `Blocked`, `Untested`, or `Inconclusive`.
- Do not infer backend/data correctness from a successful UI render alone. Verify API, persistence, logs, or returned data when the requirement depends on data flow.
- Do not hide untested areas. If something was not tested, mark it `Untested`. If it could not be tested, mark it `Blocked` and state the blocker.
- Do not collapse multiple requirement points into one generic pass. Each explicit acceptance criterion needs its own status.
- Do not treat mock/demo data as real data unless the requirement explicitly accepts mock data.
- Do not use stale screenshots, unreadable placeholder images, old report data, or previous-run results as current evidence unless the report labels them as historical context. Passed requirements must cite evidence marked `current_run: true`; screenshot evidence must point to a readable PNG/JPEG image; when `results.json.startedAt` exists, current-run file evidence should be generated during or after that run.
- Do not cite evidence for a `Passed` requirement or test when the evidence lineage belongs to another requirement or test. Runner-generated evidence should carry `requirement_ids` and `test_ids`; if lineage exists, it must match the cited item. When `results.json` is available, evidence generated by `ledger_from_probe.py` must also bind to a matching current results step by scenario, step id/action, lineage, and status, and copied fields such as status code, checked JSON, matched text, message counts, runtime counts, headers, and artifact paths must be preserved and match the bound step; do not delete copied runner fields and replace them with free-text assertions.
- Do not accept generic success text as current-run proof when stale seed data, cached responses, or front-end fallback text could match. Use the runner's generated `qa_marker` and assert that the returned stream/API/persistence evidence contains it when the feature can echo or persist user-provided content.
- Do not treat ledger text-match fields as self-proving. Matched or forbidden response, message, request body, stdout, or stderr text must reference a captured artifact file where the matched text is present and forbidden text is absent.
- Do not treat `checked_json`, `checked_request_json`, or `checked_stdout_json` as self-proving. They must reference a captured response, request, stream-message, or stdout artifact that parses as JSON and contains the same checked path/value pairs.
- Do not treat `extracted_json`, `extracted_stdout_json`, checked response headers, or extracted response headers as self-proving. Extracted ids, turn ids, job ids, trace ids, or statuses must match their recorded source path/header, and response header checks/extractions must include the captured `response_headers` map.
- Do not treat hand-written stream `assertions`, zero-message counts, or a bare/missing `messages_path` string as captured WebSocket/SSE message evidence. Passed stream tests need a message count greater than zero, an existing readable non-empty current-run message artifact path, matched returned message text, or checked/extracted stream-message JSON evidence.
- Do not treat hand-written `proves` or generic `assertions` text as terminal-status proof. Claims such as `answer_done`, `completed`, or terminal state need returned message text, checked response JSON/text, checked stdout JSON/text, or extracted returned/output status evidence, including for API and UI-to-API same-object reads.
- Do not treat runtime disposition fields as self-proving. If `results.json` contains console errors, failed responses, or request failures, `checked_* = 0` only proves disposition when the matching `ignored_*` count accounts for every observed runtime issue of that category; otherwise re-run a focused runtime disposition probe after the observed issue or report the issue.
- Keep evidence layers separate. UI visibility or fallback text, test seed setup, stream terminal events, same-object API reads, and persistence/log terminal state are different proof layers. Do not merge them into one pass claim.
- Do not treat `business-model.json`, `oracle-model.json`, `qa-metrics.json`, or `closeout-candidates.json` as proof. They are planning, oracle, measurement, and human-confirmation handoff artifacts; final pass still requires current-run evidence and `qa-verdict.json`.
- If evidence is ambiguous, write `Inconclusive`, explain why, and name the exact evidence still needed.
- Do not claim final pass from `audit-summary.json` alone. The audit can prove ledger structure while `qa-verdict.json` still correctly returns `failed`, `blocked`, or `inconclusive`.
- Do not mix artifacts across runs. `qa-verdict.json` must be generated from an `audit-summary.json` whose ledger/results paths, content hashes, and referenced evidence artifact hashes match the current `evidence-ledger.json`, `results.json`, and evidence files.
- Do not let `results.json.artifactDir` point to another run directory. Relative runner artifacts, copied evidence fields, and report defaults are current only when `artifactDir` matches the current ledger/results artifact directory.
- Do not generate final pass from an audit that omitted `test-matrix.json`; matrix coverage and ledger completeness must be part of the audited artifact set.
- Do not omit `--results` when `audit-summary.json` was generated with `results.json`; otherwise runtime errors, failed requests, and request failures are no longer bound to the final verdict.
- Do not omit existing sibling `defects.json`, `requirement-coverage.json`, `plan-audit-summary.json`, `service-preflight.json`, `service-runtime.json`, `adapter-probes.json`, `adapter-context.json`, or `qa-cycle-error.json` from final verdict generation; known defects, source coverage gaps, invalid plans, setup blockers, adapter blockers, environment/data boundaries, or QA pipeline failures must not be hidden by leaving artifacts out.
- Do not substitute a same-named artifact from another run for an existing current-run sibling artifact. If `defects.json`, `requirement-coverage.json`, `plan-audit-summary.json`, `service-preflight.json`, `service-runtime.json`, `adapter-probes.json`, `adapter-context.json`, or `qa-cycle-error.json` exists beside the current ledger/results, verdict and report generation must use that current artifact or block the pass claim.
- Do not run probes when `requirement-coverage.json` says requirement-source units are unmapped, unless the user explicitly wants a planning/blocker report.
- Treat unconfirmed runtime/data boundary as a first-class blocker. If `qa-verdict.json` contains both environment-boundary reason codes and other non-pass reasons such as defects, runtime gaps, or strategy gaps, confirm the environment/data boundary before reporting a product conclusion or auto-continuing follow-up probes.

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
- Do not ask for clarification unless a destructive action, production mutation, or missing credential blocks meaningful testing.
- For a first-pass artifact, run `scripts/init_qa_artifact.py` or `scripts/scaffold_requirement.py` with the requirement source. Treat the generated charter, matrix, and plan as a conservative scaffold to review, not as proof that the requirement is fully testable.
- When a project checkout is available, generate `adapter-context.json` with `scripts/discover_project_context.py` or through `scripts/init_qa_artifact.py --project-root <repo>`. Use it to state environment/data boundaries and route evidence to the right service, stream, persistence, or log layer.
- For a real backtest pass claim, set `--runtime-mode` and `--data-boundary-status` when initializing or running the cycle, then use `--require-environment-boundary` so `qa-verdict.json` blocks any pass while runtime or data boundary remains unconfirmed.

Extract these fields into a working test charter:

- User goal: what outcome the feature should produce.
- Actors and permissions: who can do it and who should not.
- Entry points: pages, buttons, commands, API endpoints, scheduled jobs, or background flows.
- Data flow: required input, API calls, persistence, derived data, displayed data, and downstream effects.
- Logic rules: validation, branching, ordering, state transitions, authorization, retries, idempotency.
- Interaction rules: loading, disabled states, modal behavior, keyboard/mouse basics, responsive behavior, toasts, empty/error states.
- Acceptance criteria: explicit criteria from the requirement plus implicit criteria needed for the feature to work end to end.
- Business model: actors, entities, workflows, state transitions, rules, entry points, and agent-team handoff boundaries.
- Oracle model: requirement-specific pass rules, required evidence layers, weak signals to avoid, and blocked-until inputs.
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

For strict evidence ledgers, read `references/evidence-ledger-schema.md` before deciding final statuses.

Do not include stale page lists just because a previous run used them. Add a route, API, or interaction only when the current requirement or discovered dependency justifies it.

Before execution, perform a coverage check:

- The target environment, data boundary, service status, and adapter assumptions are recorded in `adapter-context.json` or explicitly documented in the charter.
- Every explicit requirement has at least one planned test.
- Every important data dependency has an API/log/persistence verification method or a documented blocker.
- Every create/update/delete flow has a safe test-data strategy.
- Every user-visible workflow has an interaction check for loading, disabled, validation, success, and error states when applicable.
- Every planned assertion names the evidence that will prove or disprove it.

## Execution

Use the lightest reliable evidence for each claim:

- Browser/UI: Playwright, in-app browser, or Chrome when login state is required.
- API/data flow: direct HTTP probes, application logs, database reads, or existing project test helpers. Prefer helper commands that print JSON and assert them with `expectStdoutJson` / `extractStdoutJson` instead of loose stdout text checks when verifying persistence state. Use response-header assertions or `extractResponseHeader` when trace ids, cache/content-type, auth-dependent headers, or gateway routing are part of the proof.
- Logic: combine UI behavior with API/state evidence rather than relying on visual checks alone.
- Interaction: verify click targets with `expectClickable` before important clicks, use `clickAndWaitForResponse` when a click must prove API/data continuity, plus form validation, loading/disabled states, modal lifecycle, navigation, toasts, empty states, and responsive breakpoints.
- UI blockers: handle optional onboarding, modals, masks, and locale/copy variants explicitly with planned dismiss/assertion steps. Treat visible-but-not-clickable controls as a separate interaction failure with hit-test blocker evidence, not as a visual pass.
- Errors: capture console errors, failed requests, HTTP 4xx/5xx, unhandled exceptions, traceback/log snippets, and user-visible error states.
- Cross-step state: when a stream/API creates a session, turn, job, upload, or trace id, use `extractJson`, `extractResponseHeader`, and later `{ "var": "..." }` references or `pathTemplate` placeholders such as `/api/items/{id}` so follow-up API, command, log, or persistence probes verify the same object. For current-run proof, inject `qa_marker` with `{ "var": "qa_marker" }` or `{ "template": "..." }`, enable `captureRequestBody` when the request payload itself is part of the claim, assert request-side payload with `expectRequestTextContains` or `expectRequestJson`, and assert the same marker appears in the returned API, stream, log, or persistence layer. Use `captureResponseHeaders` only when the header set itself is evidence. For asynchronous jobs or sessions, use `pollApi` to repeat the same-object read until the terminal status assertion passes or the poll timeout is reached. For authorized create/update/delete flows in a test environment, include a safe test-data cleanup strategy; use `cleanupApi` with `alwaysRun` and `skipIfMissingVars` when a created runtime id must be removed after assertions.
- Failure diagnostics: for WebSocket/SSE/API flows, prefer plans that can keep running after a terminal error when diagnostic identifiers are available. Use scenario-level `continueOnFailure` with downstream checks to distinguish stream failure, session persistence, and database status instead of collapsing them into one vague failure.
- Layer gates: `stream`/`websocket`/`sse` tests that pass must cite WebSocket/SSE message evidence; `api` and `ui_to_api` tests must cite API/click-to-response evidence; `persistence` tests must cite persistence/log/API evidence. Claims about current-run markers, stale seed avoidance, fallback avoidance, `answer_done`, or `completed` need returned marker or terminal-status evidence, not only request text or screenshots. Returned marker evidence must come from returned message/response/stdout text or checked returned JSON that contains the actual marker value; request-body marker evidence alone does not count.

Default artifact layout:

```text
<out-dir>/<timestamp>-<slug>/
├── requirement.md
├── business-model.json
├── oracle-model.json
├── qa-metrics.json
├── closeout-candidates.json
├── semantic-artifacts-summary.json
├── adapter-context.json
├── adapter-probes.json
├── service-preflight.json
├── service-runtime.json
├── test-charter.md
├── test-matrix.json
├── test-plan.json
├── scaffold-summary.json
├── requirement-coverage.json
├── plan-audit-summary.json
├── results.json
├── evidence-ledger.json
├── audit-summary.json
├── defects.json
├── next-probes.json
├── next-probe-application.json
├── qa-cycle-error.json
├── qa-verdict.json
├── qa-agent-summary.json
├── qa-agent-handoff.md
├── qa-run-summary.json
├── screenshots/
├── evidence/
└── report.md
```

Helpful scripts:

- `scripts/init_qa_artifact.py`: create a run folder and scaffold requirement, business model, oracle model, charter, matrix, plan, metrics, closeout candidates, summary, and initial ledger files. Missing, unreadable, or directory-shaped requirement input files, plus unreadable project roots discovered while generating adapter context, create a blocked run folder with `qa-initialization-error.json`, `scaffold-summary.json` `input_artifact_errors`, and a blocked initial ledger, then exit non-zero instead of crashing or fabricating probes from invalid scope.
- `scripts/discover_project_context.py`: inspect a checkout for adapter/environment context, service ports, config boundaries, package scripts, and evidence-layer warnings without reading secret values. Missing, file-shaped, or unreadable project roots are written to `adapter-context.json` as `input_artifact_errors` with `project_root_status.readable=false` and exit non-zero instead of silently producing a generic no-service context.
- `scripts/preflight_runtime.py`: verify required service ports, start-command executables, npm scripts, and env/config file paths before execution. It writes `service-preflight.json` and never reads secret values or starts services by default. During `--refresh-context`, preserve custom services from the existing `adapter-context.json` and re-probe their readiness so post-start checks verify the same service ids. Explicit `--required-service` ids missing from adapter context are blockers. Missing, unreadable, directory-shaped, malformed, or non-object adapter-context/plan inputs, plus unreadable project roots discovered during refresh, are written to `service-preflight.json` as `input_artifact_errors` and exit non-zero instead of crashing or synthesizing a start plan.
- `scripts/service_runtime.py`: dry-run or explicitly start missing local/test services from `service-preflight.json` `start_plan`. It writes `service-runtime.json` with PID, command, cwd, stdout/stderr log paths, and port-readiness evidence. Omit `--start` for a dry-run; use `--stop` only for PIDs recorded by the same runtime artifact. Missing, unreadable, directory-shaped, malformed, or non-object preflight/runtime inputs are written to service runtime artifacts as `input_artifact_errors` and exit non-zero without starting or stopping services.
- `scripts/synthesize_adapter_probes.py`: convert adapter context plus matrix/plan into executable adapter probes or explicit blockers. For OPC stream checks it can synthesize WebSocket `answer_done` + returned-marker evidence, same-session API verification, and optional read-only persistence helper checks. Missing, unreadable, directory-shaped, malformed, or non-object adapter-context/plan/matrix inputs are written to `adapter-probes.json` as `input_artifact_errors`; `--apply` does not rewrite plan/matrix when inputs are invalid.
- `scripts/scaffold_requirement.py`: derive a conservative first-pass `business-model.json`, `oracle-model.json`, `test-charter.md`, `test-matrix.json`, `test-plan.json`, `qa-metrics.json`, `closeout-candidates.json`, and `scaffold-summary.json` from requirement text. It generates runnable UI/read-only API probes when entry points are explicit, adds `expectClickable` interaction probes for inferable button/click requirements, generates `clickAndWaitForResponse` UI-to-API probes when the same requirement names a click target and API path, can extract ids from an authorized click response and verify a same-object read-only follow-up API via `pathTemplate` or `pollApi` when asynchronous terminal status is mentioned, adds `cleanupApi` teardown probes for authorized create flows with same-object ids, and marks stream, persistence, permission, placeholder, unlocatable click targets, unsafe click-to-response mutations, or mutating checks as blocked until the needed auth, payload, helper, selector, or safe test data is supplied. Missing, unreadable, or directory-shaped requirement inputs are written to `scaffold-summary.json` as `input_artifact_errors` with blocked matrix/ledger-compatible artifacts and no product probes.
- `scripts/refresh_semantic_artifacts.py`: regenerate `business-model.json`, `oracle-model.json`, `qa-metrics.json`, and `closeout-candidates.json` from the current `requirement.md`, `test-matrix.json`, and `test-plan.json`, then write `semantic-artifacts-summary.json`. Semantic artifacts must carry `not_evidence=true` plus `source_bindings`; missing or stale bindings block report rendering instead of letting old planning context look like current-run evidence. Missing requirement text is a warning, but missing or malformed matrix/plan inputs are blockers.
- `scripts/audit_requirement_coverage.py`: compare `requirement.md` source units against `test-matrix.json` and fail before execution when any behavior point is not mapped to a requirement row. Missing, unreadable, directory-shaped, malformed, or non-object requirement/matrix inputs are written to `requirement-coverage.json` as `input_artifact_errors` and exit non-zero instead of crashing or silently allowing probes.
- `scripts/validate_plan.py`: validate `test-plan.json` against `test-matrix.json` before execution and write `strategy_coverage` so the agent can see which planned dimensions (`ui`, `interaction`, `api`, `stream`, `persistence`, `permission`, `runtime`, `responsive`, `cleanup`, `logic`) have direct executable probe coverage. It separates planned dimensions from observed step dimensions, so an incidental UI/navigation step does not count as permission, persistence, stream, or runtime coverage unless the step itself proves that dimension. It treats runtime-disposition tests as runtime coverage even when their text mentions failed responses, requests, or `results.json`, so runtime diagnostics do not create false API coverage gaps unless the test explicitly asks for API/endpoint/path/poll behavior. Missing, unreadable, directory-shaped, malformed, or non-object plan/matrix inputs are written to `plan-audit-summary.json` as `input_artifact_errors` and exit non-zero instead of crashing or silently skipping validation. Missing, directory-shaped, unreadable, or invalid JSON Playwright `storageState` auth files block at plan validation time instead of becoming browser execution failures.
- `scripts/run_qa_cycle.py`: orchestrate semantic artifact refresh, plan validation, probe execution, ledger generation, evidence audit, and report generation. It clears stale terminal `qa-verdict.json`, `report.md`, and `qa-cycle-error.json` files or directories at the start of a new cycle so an early failure cannot leave an old pass/report/error in place. Early blocker handoff verdicts must include only artifacts produced in the current cycle, plus stable input context such as valid `adapter-context.json`; stale execution artifacts such as old results, audits, ledgers, semantic artifacts, or defects are omitted and recorded in `qa-run-summary.json`. Missing, unreadable, directory-shaped, or non-object required `test-plan.json` or `test-matrix.json` artifacts become `qa-cycle-error.json` and non-pass `qa-verdict.json` handoffs rather than bare summary failures or downstream helper tracebacks. Unreadable or directory-shaped `adapter-context.json` becomes an `invalid_adapter_context` handoff before environment-boundary writes, preflight, synthesis, validation, or probes run. Before validation, it refreshes semantic artifacts and marks them current only when `semantic-artifacts-summary.json` and the regenerated artifacts are produced in the current cycle. When `--skip-probe` is used, unreadable existing `results.json` artifacts become `qa-cycle-error.json` handoffs rather than Python tracebacks or reusable evidence. When runtime preflight or service startup blocks execution, it writes a blocked `qa-verdict.json` handoff before exiting non-zero. When execution reaches evidence audit but the audit fails, it writes the current `audit_failed` verdict handoff before exiting non-zero so the agent loop can report a structured inconclusive verdict instead of a generic script failure. When a cycle helper fails after or during execution, or exits zero but its required JSON output is missing, malformed, directory-shaped, or non-object, it writes `qa-cycle-error.json` and includes it in a non-pass verdict handoff.
- `scripts/playwright_probe.mjs`: execute a JSON probe plan and collect UI, click-to-response, API, WebSocket, SSE, command, screenshot, console, failed response, and request failure evidence. It redacts secret-like values in URLs, previews, stdout/stderr artifacts, request/response body artifacts, and header captures before writing results. When response/message/stdout text or JSON assertions or extractions are evaluated, it writes the source artifact automatically so later audit can verify the assertion is not self-proving; when response headers are checked or extracted, it records the redacted `response_headers` map automatically. When an earlier step stops a scenario, later non-`alwaysRun` planned steps are recorded as `skipped` with their original requirement/test lineage so partial execution cannot silently become a pass.
- `scripts/ledger_from_probe.py`: convert matrix plus probe results into a first-pass evidence ledger. Preserve captured response/request body artifact paths and bounded redacted body previews so API defects can cite root-cause evidence instead of only status codes. Missing, unreadable, directory-shaped, malformed, or non-object matrix/results inputs are written to `evidence-ledger.json` as `input_artifact_errors` and exit non-zero instead of crashing or synthesizing evidence from broken inputs.
- `scripts/audit_evidence.py`: validate requirement coverage, statuses, evidence references, current-run file freshness, evidence disposition, bundled-runner evidence lineage, bundled-runner binding to current `results.json` steps, evidence-layer gates, marker/stale-seed/fallback return gates, stream-message capture gates, terminal-status returned/output gates, type-specific assertion signals, missing evidence files, TODO placeholders, and secret-like values before final reporting, including raw Authorization/Cookie/password material while allowing `[REDACTED]` placeholders. It records content hashes for the ledger, matrix, results, and referenced evidence artifact files so final verdict generation can detect drift after audit. Generic current-run API/file evidence is proven by `current_run=true`, pass-disposition evidence, assertion signals, and freshness checks when `results.json.startedAt` exists; evidence generated by bundled runner helpers must carry matching `requirement_ids` / `test_ids` and, when results are provided, match a current results step by scenario, step id/action, lineage, status, and preserved copied evidence fields; returned marker evidence is required only when the claim depends on marker echo, stale seed avoidance, or fallback avoidance, and arbitrary non-marker `checked_json` values do not satisfy that gate; checked/extracted JSON fields must be backed by a referenced source artifact and cannot self-prove from ledger fields alone; checked/extracted response headers must be backed by captured `response_headers`; runtime disposition evidence must be consistent with the observed `results.json` counts, so `checked_* = 0` cannot hide actual runtime issue arrays unless the matching `ignored_*` count covers them; passed stream tests require positive captured message count or an existing readable non-empty message artifact path, matched returned message text, or checked/extracted stream-message JSON instead of hand-written assertions, missing paths, or zero-message counts; terminal/completed claims in stream, API, UI-to-API, or persistence tests require structured returned or output evidence such as matched stream/API/command text, checked JSON, checked stdout JSON, or extracted returned/output status, not hand-written `proves` text. Missing, unreadable, directory-shaped, malformed, or non-object ledger/matrix/results inputs are written to `audit-summary.json` as `input_artifact_errors` and exit non-zero instead of crashing or silently treating the audit as complete.
- `scripts/generate_defects.py`: convert failed tests, evidence, and undispositioned runtime issues from `results.json` into structured defect findings with severity, layers, expected/actual, inference, repro steps, and evidence refs. Runtime issue findings are suppressed only when count-aware disposition evidence shows `checked_* = 0` and the matching `ignored_*` count covers every observed issue in that category. When API evidence has a captured response body, carry the redacted body preview and artifact path into the finding so reports and next probes can reason from observed backend output. Missing, unreadable, directory-shaped, malformed, or non-object ledger/results/matrix inputs are written to `defects.json` as `input_artifact_errors` and exit non-zero instead of crashing or fabricating findings.
- `scripts/generate_next_probes.py`: convert structured defects plus blocked/untested/inconclusive ledger items into recommended follow-up probes for the next diagnostic turn, including targeted runtime disposition probes for console errors, failed HTTP responses, and request failures. It records `generated_from` source paths plus `generated_from_hashes` so later application can detect source artifact drift. Failed HTTP runtime findings with a captured endpoint should also produce a same-endpoint API body-capture diagnostic when safe. API follow-ups should reuse the observed failed API path plus safe non-secret query parameters from evidence `locator`, `observed_url`, `error`, or defect `actual` text when available; do not require manual failed-path input for a path already captured in current-run evidence, and do not preserve token/cookie/key/secret query parameters in generated plans. Same-object follow-up variables such as `session_id` and `turn_id` must be extracted from the current results step matched by scenario id, step id/action, and requirement/test lineage, not by `stepId` alone. When failed API/body evidence contains `trace_id`, `request_id`, or `correlation_id`, generate a log-correlation command recommendation that remains behind the command safety gate until explicitly allowed. Missing, unreadable, directory-shaped, malformed, or non-object defects/results/ledger inputs are written to `next-probes.json` as `input_artifact_errors` and exit non-zero instead of crashing or inventing follow-up probes.
- `scripts/apply_next_probes.py`: apply safe, concrete, non-duplicate next-probe recommendations back into `test-plan.json` and `test-matrix.json`; stream, command, mutating API, auth, placeholder, requirement/test-lineage-free, missing-source, cross-run `generated_from`, and source-hash-mismatched recommendations remain blocked unless explicitly repaired into a fully concrete current-run mapped probe. Do not treat a same-path API follow-up as a duplicate when it adds diagnostic capture such as `captureBody`, response-header capture, response text checks, or returned JSON extraction that the original failing step lacked. Run-level runtime disposition recommendations are safe to apply and create a runtime matrix row when no requirement-specific test owns them yet. Unreadable, missing, directory-shaped, malformed, non-object, missing current-run source binding, missing source hashes, current-run source-mismatched, source-hash-mismatched, or upstream `input_artifact_errors`-bearing next-probe input artifacts are written to the preview/application artifact as `input_artifact_errors` and exit non-zero instead of crashing or silently applying a partial follow-up.
- `scripts/generate_verdict.py`: combine the audited ledger, plan validation summary, strategy coverage gaps, runtime results, service preflight/runtime artifacts, adapter blockers, cycle helper errors, and defects into a strict final verdict, independently rechecking count-aware runtime disposition, runner-evidence step and field binding against `results.json`, `results.json.artifactDir` binding, audit-bound evidence artifact content hashes, current-run sibling artifact paths, and `defects.json` summary/findings consistency. Unreadable, directory-shaped, malformed, or non-object input artifacts become `input_artifact_unreadable` verdict reasons and `input_artifact_errors` entries instead of tracebacks; `--fail-on-not-pass` may exit non-zero but must still write the verdict. Only `verdict=passed` with `can_claim_pass=true` allows a pass claim.
- `scripts/generate_report.py`: convert a plan and results JSON into a Markdown QA report, including business model, oracle model, QA metrics, and closeout-candidate sections only when those semantic artifacts are source-bound to the current requirement/matrix/plan chain. Reports separate all-Passed ledger status from the final pass claim: only `qa-verdict.json` with `can_claim_pass=true`, bindings to the current report ledger/audit/results/evidence artifacts, `results.json.artifactDir`, current-run sibling conclusion artifacts, and no contradictory conclusion artifacts such as failed `plan-audit-summary.json`, strategy coverage gaps, late or mismatched `defects.json`, failed requirement coverage, setup blockers, adapter blockers, unconfirmed environment boundaries, or stale/missing semantic source bindings allows pass wording. Missing, stale, unbound, contradictory, cross-run, or non-pass verdicts render an explicit no-pass guard. Missing or mismatched semantic bindings render a `Semantic Artifact Binding Guard` section and suppress semantic artifact body rendering so fabricated or stale planning context cannot appear as current context. Unreadable, missing, directory-shaped, malformed, or non-object report input artifacts are rendered into a partial report `Report Input Errors` section and exit non-zero instead of crashing with a traceback or silently omitting the bad input.
- `scripts/qa_agent_loop.py`: run a bounded QA/backtest agent loop over a run directory. It initializes or resumes runs, executes `run_qa_cycle.py`, previews and hash-binds safe next probes, applies them only when allowed, snapshots each iteration, writes `qa-agent-summary.json`, `loop_control`, and `qa-agent-handoff.md`, and stops on pass, blocker, no safe progress, failure, or max iterations. Before running, interpreting, or modifying this loop, read `references/agent-loop-contract.md`; it is the authoritative contract for artifact currentness, failure-category routing, route-model projections, self-convergence, evidence-gap operations, and handoff reliability.
- `scripts/regression_check.py`: run isolated self-regression fixtures for the skill helpers after modifying this skill. It checks coverage gates, verdict gates, service runtime dry-run, next-probe/agent-loop flow, API failed-path reuse for diagnostic follow-ups, a two-iteration runtime auto-recovery loop, and a full skip-probe QA cycle without touching the target project. Add `--with-browser` when you need stronger local Playwright/Chrome fixtures that prove visible-but-not-clickable blocker evidence reaches the ledger, defects, and report, and that a live local WebSocket/API/persistence backtest can produce a passing verdict.

Scripts are helpers, not a substitute for judgment. Patch or extend the generated plan for the requirement under test before running it.

When authentication is required, use env references in the plan, such as `{ "env": "OPC_QA_TOKEN", "prefix": "Bearer " }`, and pass the value through the execution environment. For browser login state, use `storageState` or `contextOptions.storageState` with a file path or an env reference to a file path, such as `{ "env": "OPC_QA_STORAGE_STATE" }`; `validate_plan.py` must confirm that the file exists, is not a directory, and contains JSON before execution. Inline `storageState` objects with `cookies` or `origins`, direct auth-like headers, direct auth-like `runtimeVars` / `vars`, direct auth-like API `json`/object `body` fields, direct command `env` values, direct auth-like `setLocalStorage`, and direct `addCookies` values such as `Authorization`, `auth_token`, `password`, `oc_token`, or `sid` are plan-validation errors; use env-backed runtime references or storage state files instead. Do not write raw JWTs, cookies, or API keys into `test-plan.json`, reports, or ledgers.

After execution, perform a second coverage check against the original matrix. Do not finish with a report that only lists automated steps if the requirement includes untested logic, data, permission, or interaction points. Add a coverage-gap section instead.

For a complete bundled run, prefer:

```bash
python3 scripts/run_qa_cycle.py --run-dir <run-dir> --preflight-runtime --strict-runtime --require-environment-boundary --runtime-mode test --data-boundary-status "test database; no production data"
```

This writes `business-model.json`, `oracle-model.json`, `qa-metrics.json`, `closeout-candidates.json`, `semantic-artifacts-summary.json`, `requirement-coverage.json`, `plan-audit-summary.json`, `results.json`, `evidence-ledger.json`, `audit-summary.json`, `defects.json`, `next-probes.json`, `qa-verdict.json`, `report.md`, and `qa-run-summary.json`.
When `--strict-runtime` finds only undispositioned runtime issues, the cycle continues long enough to write `defects.json`, `next-probes.json`, and `qa-verdict.json`; the verdict still blocks a pass claim.
When required plan/matrix artifacts or adapter context are missing or unreadable, or when requirement coverage, plan validation, runtime preflight, or service startup blocks execution, the cycle exits non-zero but still writes the relevant blocker/error artifact plus a blocked or non-pass `qa-verdict.json`; treat that as a planning/setup handoff, not as a product test failure.
When `audit_evidence.py` fails after probe execution, the cycle exits non-zero but still writes `audit-summary.json`, `qa-verdict.json`, and `qa-run-summary.json` with `audit_failed`; treat that as an evidence-integrity handoff, not as permission to infer pass from raw `results.json`.
When a cycle helper such as probe execution, ledger generation, defect generation, next-probe generation, verdict generation, or report generation fails, or when a helper exits zero but produces unreadable required JSON, the cycle exits non-zero but writes `qa-cycle-error.json` plus a non-pass `qa-verdict.json`; treat that as a tooling/evidence pipeline handoff, not as a product pass or product failure.

When the user asks for the skill to act like an Agent across iterations, prefer the bounded loop:

```bash
python3 scripts/qa_agent_loop.py --requirement-file <requirement.md> --base-url <local-or-test-url> --preflight-runtime --strict-runtime --require-environment-boundary --runtime-mode test --data-boundary-status "test database; no production data" --max-iterations 3
```

Use `--skip-probe` only for planning/blocker reports. Use `--allow-live-stream`, `--allow-unsafe-command`, or `--allow-mutating-api` only when the target environment and test data make those probes safe. The loop writes `qa-agent-summary.json` and per-iteration snapshots under `iterations/`; read top-level `loop_control` first for machine routing, then `next_action` for the detailed corrective action. Do not apply an existing `next-probes.json` from a prior process unless you intentionally pass `--apply-existing-next-probes`.

For a new requirement, initialize the artifact first:

```bash
python3 scripts/init_qa_artifact.py --requirement-file <requirement.md> --base-url <local-or-test-url> --runtime-mode test --data-boundary-status "test database; no production data" --entry-path <optional-ui-path>
```

Use `--allow-live-stream` only when the stream endpoint, auth state, and safe payload are known. Use `--persistence-command` only for a project-approved read-only helper. Review `scaffold-summary.json` before running the cycle; blocked items are coverage gaps, not failures and not passes. If the environment/data boundary is not known, keep `runtime_mode` or `data_boundary_status` unconfirmed and do not enable a pass claim.

If you need a planning-only report before executing Playwright, run `scripts/run_qa_cycle.py --run-dir <run-dir> --skip-probe`; when `results.json` is missing, the runner writes an explicit skipped-results stub and keeps the report in `attention` status.

If requirement coverage or plan validation fails, add missing matrix rows, fix invalid probes, or explicitly mark source units out of scope/blocked before executing product probes. Use `--allow-unmapped-requirement-source` only to create a warning/blocker artifact, not to claim a successful pass.

After a cycle has produced `next-probes.json`, apply only safe concrete follow-ups before the next execution:

```bash
python3 scripts/apply_next_probes.py --run-dir <run-dir> --apply
```

For live stream follow-ups, add `--allow-live-stream` only when the target environment, auth state, and payload are approved. For the bundled loop, use `run_qa_cycle.py --apply-next-probes` to apply an existing `next-probes.json` before validation and execution.

For adapter-aware runs, synthesize probes before execution:

```bash
python3 scripts/synthesize_adapter_probes.py --run-dir <run-dir> --allow-live-stream --apply
```

Add `--persistence-command '<read-only-helper> {session_id}'` only when that helper is approved for the target environment. If services are currently stopped, leave the probes blocked or use `--allow-stopped-service` only to prepare a plan for later execution, not to claim the run passed.

For local service readiness, run:

```bash
python3 scripts/preflight_runtime.py --run-dir <run-dir> --refresh-context --fail-on-blockers
```

If this reports blockers, use `service-preflight.json` as the handoff for what to start or configure. Do not run broad probes until required services are reachable unless the run is explicitly a setup/blocked-state report.

When the user authorizes local/test service startup, start only from the generated start plan:

```bash
python3 scripts/service_runtime.py --run-dir <run-dir> --start
python3 scripts/preflight_runtime.py --run-dir <run-dir> --refresh-context --fail-on-blockers
```

For the bundled loop, use:

```bash
python3 scripts/run_qa_cycle.py --run-dir <run-dir> --preflight-runtime --start-missing-services --strict-runtime
```

Do not use service startup for production or unknown environments. If startup fails or readiness stays false, stop before product probes and report the setup blocker with `service-runtime.json` and log paths.

For manual/custom runs, update `evidence-ledger.json` and run:

```bash
python3 scripts/audit_evidence.py --matrix <run-dir>/test-matrix.json --ledger <run-dir>/evidence-ledger.json --summary <run-dir>/audit-summary.json
```

When `results.json` is available, pass `--results <run-dir>/results.json`. Use `--strict-runtime` when unexplained console errors, failed requests, or request failures should fail an otherwise all-passed run.

If the audit fails, do not claim the run passed. Fix the ledger, collect missing evidence, or mark items `Failed`, `Blocked`, `Untested`, or `Inconclusive` with notes.

After changing this skill itself, run:

```bash
python3 scripts/regression_check.py
```

This is a skill-maintenance check, not a product QA run. It should pass before trusting changes to the helper scripts or report/verdict flow.

When browser launch is available and approved, also run:

```bash
python3 scripts/regression_check.py --with-browser
```

This optional stronger check launches local fixtures and verifies `expectClickable` records the blocking element through `results.json`, `evidence-ledger.json`, `defects.json`, and `report.md`. It also starts a deterministic local HTTP/WebSocket service and proves a live `answer_done` stream, same-session API read, and read-only persistence helper can pass through `run_qa_cycle.py` to `qa-verdict.json`.

For a standalone final gate, run:

```bash
python3 scripts/generate_verdict.py --ledger <run-dir>/evidence-ledger.json --audit-summary <run-dir>/audit-summary.json --results <run-dir>/results.json --defects <run-dir>/defects.json --plan-audit-summary <run-dir>/plan-audit-summary.json --requirement-coverage <run-dir>/requirement-coverage.json --out <run-dir>/qa-verdict.json --fail-on-not-pass
```

Pass `--service-preflight`, `--service-runtime`, `--adapter-context`, `--adapter-probes`, `--cycle-error`, and `--require-environment-boundary` when those artifacts exist and the run is intended to support a real pass claim. If `--fail-on-not-pass` exits non-zero, the report may still be useful as a failure/blocker report, but it must not be phrased as a successful backtest.
If any provided verdict input artifact is malformed or unreadable, read `input_artifact_errors` in `qa-verdict.json`; that is an evidence-integrity failure, not permission to infer pass from the remaining artifacts.

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
- Current-run marker when used: `qa_run_id` / `qa_marker` and where it was observed
- Business intent model and oracle model, labeled as planning/oracle context rather than proof
- QA metrics and closeout candidates, labeled as human-confirmation handoff rather than automatic memory or skill updates
- Requirement source coverage from `requirement-coverage.json`
- Evidence audit summary from `audit-summary.json`
- Final verdict from `qa-verdict.json`
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

- Never log passwords, tokens, session cookies, API keys, or private credentials in reports.
- Do not mutate production data unless the user explicitly authorizes that exact destination and action.
- Prefer test data or clearly reversible actions for create/update/delete flows.
- If testing requires sending personal data or inviting external users, confirm first.
- Keep unrelated repo changes out of QA runs unless the user requests fixes.
