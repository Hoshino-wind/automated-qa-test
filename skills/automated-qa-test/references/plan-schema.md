# QA Probe Plan Schema

`scripts/playwright_probe.mjs` runs a schema-v2 JSON probe plan. Formal schemas live under `references/schemas/`. It is a browser-first runner with API, WebSocket, SSE, and local command probes so a QA/backtest run can verify UI behavior, data/API continuity, stream completion, persistence/log checks, and runtime errors in one artifact.

Do not run untrusted plans. `command` steps execute local commands.

## Minimal Plan

```json
{
  "schemaVersion": 2,
  "baseUrl": "http://127.0.0.1:3000",
  "artifactDir": "/tmp/automated-qa-test/run",
  "headless": true,
  "scenarios": [
    {
      "id": "main-flow",
      "title": "Main requirement flow",
      "steps": [
        {
          "action": "goto",
          "id": "T1-open",
          "testIds": ["T1"],
          "requirementIds": ["R1"],
          "path": "/",
          "proves": "The entry point opens."
        },
        {
          "action": "expectText",
          "id": "T1-visible-title",
          "testIds": ["T1"],
          "requirementIds": ["R1"],
          "text": "Dashboard",
          "proves": "The dashboard title is visible."
        },
        {
          "action": "screenshot",
          "id": "T1-screenshot",
          "testIds": ["T1"],
          "requirementIds": ["R1"],
          "name": "dashboard",
          "evidenceType": "screenshot",
          "proves": "The visible dashboard state has current-run image evidence."
        }
      ]
    }
  ]
}
```

## Top-Level Fields

- `schemaVersion`: Use `2` for the expanded runner.
- `baseUrl`: Base URL for relative `path` values.
- `artifactDir`: Optional output directory. Defaults to the directory containing the plan.
- `viewport`: Optional `{ "width": 1440, "height": 980 }`.
- `headless`: Optional boolean. Defaults to `true`.
- `channel`: Optional browser channel such as `chrome`. On macOS the runner falls back to Chrome if bundled Chromium is unavailable.
- `contextOptions`: Optional Playwright browser context options. `contextOptions.storageState` is supported when top-level `storageState` is absent.
- `storageState`: Optional Playwright storage state file path or env reference to a file path. `validate_plan.py` fails before browser execution if the referenced file is missing, a directory, unreadable, invalid JSON, or not a JSON object. Inline `storageState` objects that embed `cookies` or `origins` are validation errors; put Playwright storage JSON in a file and reference that file instead.
- `extraHTTPHeaders` / `defaultHeaders`: Optional HTTP headers. Never hardcode secrets into committed plans. Auth-like headers such as `Authorization`, `Cookie`, and `X-API-Key` must use env references.
- `captureWebSockets`: Optional boolean. Defaults to `true`.
- `maxArtifactChars`: Max characters stored in text evidence files. Defaults to `10000`.
- `qaRunId` / `qaMarker`: Optional fixed current-run identifiers. If omitted, the runner generates `qa_run_id` and `qa_marker` and records them in `results.run`.
- `runtimeVars` / `vars`: Optional non-secret runtime variables available to `{ "var": "name" }`, `{ "template": "value-{name}" }`, `pathTemplate`, `urlTemplate`, and `responsePathTemplate`. Auth-like variable names such as `auth_token`, `session_token`, `sid`, `cookie`, or `api_key` must use env references, not direct values.
- `scenarios`: Required array of scenarios.

## Shared Step Fields

Every evidence-producing step should include:

- `id`: Stable step id.
- `testIds`: Matrix test ids this step supports.
- `requirementIds`: Matrix requirement ids this step supports.
- `evidenceType`: Evidence category such as `screenshot`, `api_response`, `websocket`, `command`, `ui_assertion`, or `network`.
- `proves`: The exact claim this step can prove if it passes.
- `continueOnFailure`: Optional boolean. Defaults to `false`.
- Scenario-level `continueOnFailure`: Optional boolean. Continue later steps in that scenario after a failed step.
- `timeoutMs`: Optional per-step timeout.

The runner writes `results.json`, `screenshots/`, and `evidence/`. Secret-like URL/query/header/body/stdout/stderr values are redacted before results and evidence files are written. Use `scripts/ledger_from_probe.py` to convert mappable step results into `evidence-ledger.json`.

If a step fails and neither the step nor scenario enables `continueOnFailure`, later non-`alwaysRun` steps in that scenario are still written to `results.json` with `status: "skipped"` and their original `testIds` / `requirementIds`. This lets `ledger_from_probe.py` mark partially executed tests as `Inconclusive` instead of silently passing from earlier setup evidence.

## Runtime Variables And Current-Run Markers

Every run starts with generated runtime variables:

- `qa_run_id`: Unique id for this probe run.
- `qa_marker`: Unique marker string for proving current-run data instead of stale seed, fallback, or old response data.
- `qa_started_at`: Run start timestamp.

Use `{ "var": "qa_marker" }` when a field value should be exactly the marker. Use `{ "template": "probe-{qa_marker}" }` when the marker must be embedded in a larger string. Template values are not URL-encoded by default; `pathTemplate`, `urlTemplate`, and `responsePathTemplate` continue to URL-encode placeholders unless `encodePathVars: false` is set.

Returned-marker expectations are audit signals, not just runner assertions. When `expectMessageTextContains`, `expectResponseTextContains`, or `expectStdoutContains` passes, the runner records `messageTextContainsMatched`, `responseTextContainsMatched`, or `stdoutContainsMatched`; `ledger_from_probe.py` preserves these as `message_text_contains_matched`, `response_text_contains_matched`, and `stdout_contains_matched`. Use returned-side expectations for current-run marker, stale seed avoidance, fallback avoidance, stream completion, and persistence completion claims. `expectRequestTextContains` only proves the request payload, not the returned answer or persisted state.

Marker example:

```json
{
  "action": "api",
  "id": "T-current-run-api",
  "testIds": ["T-current-run"],
  "requirementIds": ["R-current-run"],
  "method": "POST",
  "path": "/api/v1/messages",
  "json": {
    "message": { "template": "qa probe {qa_marker}" }
  },
  "expectStatus": 200,
  "expectRequestTextContains": { "var": "qa_marker" },
  "expectRequestJson": {
    "message": { "op": "contains", "value": { "var": "qa_marker" } }
  },
  "expectJson": {
    "reply": { "op": "contains", "value": { "var": "qa_marker" } }
  },
  "captureRequestBody": true,
  "captureBody": true,
  "evidenceType": "api_response",
  "proves": "The response contains the current-run marker, not stale or seed data."
}
```

## Secret-Safe Environment References

Any plan value may reference an environment variable instead of storing a secret:

```json
{
  "storageState": { "env": "QA_STORAGE_STATE" },
  "defaultHeaders": {
    "Authorization": { "env": "QA_AUTH_TOKEN", "prefix": "Bearer " }
  },
  "scenarios": [
    {
      "id": "auth",
      "steps": [
        {
          "action": "setLocalStorage",
          "id": "T-auth-token",
          "testIds": ["T-auth"],
          "requirementIds": ["R-auth"],
          "path": "/",
          "values": {
            "app_token": { "env": "QA_AUTH_TOKEN" }
          },
          "evidenceType": "auth_setup",
          "proves": "The browser context received a token from the execution environment."
        }
      ]
    }
  ]
}
```

`validate_plan.py` fails if a referenced environment variable is missing. For `storageState`, it also validates the resolved file before Playwright runs; missing auth state is a setup blocker, not product-failure evidence. Inline `storageState` objects with `cookies` or `origins`, direct auth-like headers such as `Authorization`, direct auth-like `runtimeVars` / `vars` such as `auth_token`, direct auth-like API JSON/body fields such as `password` or `api_key`, direct command `env` values such as `API_KEY`, direct auth-like `setLocalStorage` values such as `oc_token`, and direct session/auth cookie values such as `sid` are validation errors; use `{ "env": "..." }`, a runtime variable reference backed by env for step-level headers, or a storage state file. Reports and ledgers receive redacted output; do not put raw tokens directly in plans.

## Runtime Variable Extraction

API, WebSocket, and SSE steps can extract JSON fields into runtime variables for later steps. This is how one QA cycle proves a single real turn across stream, API, persistence, logs, or command checks.

```json
{
  "action": "websocket",
  "id": "T-stream-done",
  "path": "/api/v1/agents/ask/ws",
  "send": { "question": "QA marker" },
  "expectJson": { "type": "answer_done" },
  "extractJson": {
    "session_id": "session_id",
    "turn_id": "turn_id"
  },
  "captureMessages": true
}
```

Later values can reference the extracted variable:

```json
{
  "action": "api",
  "id": "T-session-persisted",
  "path": { "var": "session_id", "prefix": "/api/v1/sessions/" },
  "expectJson": {
    "id": { "var": "session_id" },
    "messages[1].role": "assistant"
  }
}
```

Runtime references use `{ "var": "name" }` or `{ "$var": "name" }` and support `prefix`, `suffix`, and `json: true`, matching environment references. `validate_plan.py` warns when a variable is referenced before an earlier `extractJson` producer. Reports redact extracted values whose names look secret-like.

String templates can use runtime variables inside `pathTemplate`, `urlTemplate`, and `responsePathTemplate`. Template values such as `/api/v1/items/{id}` are URL-encoded by default; set `encodePathVars: false` only when the extracted value is already a safe path segment. `extractJson` specs may use a single `path` or a candidate `paths` array; the runner records the path that matched in `extractedJsonPaths`.

Use `expectJsonAny` when semantically equivalent response schemas may place the same value at a small set of known paths. It is an array of normal `expectJson` objects; the runner passes when one alternative matches and records `checkedJsonAlternativeIndex`.

Same-object follow-up example:

```json
[
  {
    "action": "clickAndWaitForResponse",
    "id": "T-create-click",
    "role": "button",
    "name": "Create",
    "method": "POST",
    "responseUrlContains": "/api/v1/items",
    "expectStatus": 200,
    "extractJson": {
      "id": { "paths": ["id", "data.id", "result.id"] }
    },
    "captureBody": true,
    "evidenceType": "ui_to_api",
    "proves": "Clicking Create returns the runtime item id."
  },
  {
    "action": "api",
    "id": "T-created-item-readable",
    "method": "GET",
    "pathTemplate": "/api/v1/items/{id}",
    "expectStatus": 200,
    "expectJsonAny": [
      { "id": { "var": "id" } },
      { "data.id": { "var": "id" } },
      { "result.id": { "var": "id" } }
    ],
    "captureBody": true,
    "evidenceType": "api_response",
    "proves": "The same extracted item id is readable through the detail API."
  }
]
```

When a stream step receives a terminal JSON error, extraction runs before the step is marked failed. Use scenario-level `continueOnFailure: true` when later diagnostic steps should still query the extracted `session_id`, `turn_id`, job id, or trace id.

Before running probes, validate the plan:

```bash
python3 scripts/validate_plan.py --plan <run-dir>/test-plan.json --matrix <run-dir>/test-matrix.json --summary <run-dir>/plan-audit-summary.json
```

For the normal bundled loop, use:

```bash
python3 scripts/run_qa_cycle.py --run-dir <run-dir> --strict-runtime
```

`run_qa_cycle.py` runs plan validation, probe execution, ledger generation, evidence audit, and report generation. It writes `qa-run-summary.json`.

## Browser/UI Steps

- `goto`: `{ "action": "goto", "path": "/route" }` or `{ "action": "goto", "url": "https://..." }`. Defaults to `waitUntil: "domcontentloaded"`; add an explicit `waitForLoadState` step when the requirement needs network quiescence.
- `setLocalStorage`: open an origin/path and set localStorage values, `{ "action": "setLocalStorage", "path": "/", "values": { "key": "value" } }`
- `addCookies`: add browser cookies, `{ "action": "addCookies", "cookies": [{ "name": "sid", "value": "...", "domain": "127.0.0.1", "path": "/" }] }`
- `clickText`: click visible text, `{ "action": "clickText", "text": "Submit" }`
- `clickRole`: click by role/name, `{ "action": "clickRole", "role": "button", "name": "Submit" }`
- `click`: click by `selector`, `text`, `role/name`, `label`, `placeholder`, or `testId`
- `clickAndWaitForResponse`: register a response listener, verify clickability, click the locator, then capture/assert the matching response without a race between click and wait
- `fillLabel`: fill by label, `{ "action": "fillLabel", "label": "Email", "value": "test@example.com" }`
- `fillPlaceholder`: fill by placeholder, `{ "action": "fillPlaceholder", "placeholder": "Search", "value": "abc" }`
- `fill`: fill by generic locator fields
- `press`: press a key on the page, `{ "action": "press", "key": "Enter" }`
- `wait`: fixed wait, `{ "action": "wait", "ms": 1000 }`
- `waitForLoadState`: wait for `load`, `domcontentloaded`, or `networkidle`
- `waitForResponse`: wait for a response matching `urlContains` or `urlPattern`, optionally `expectStatus`
- `expectText`: assert visible text
- `expectAnyText`: assert at least one visible text from `texts`, useful for language or copy variants
- `expectVisible` / `expectHidden`: assert locator visibility
- `expectClickable`: assert a locator is visible, enabled, not inert, receives pointer events at its center point, and passes Playwright trial-click actionability without performing the click
- `expectLocatorCount`: assert `expectCount`, `expectAtLeast`, or `expectAtMost`
- `expectUrlContains`: assert current URL contains text
- `expectNoConsoleErrors`: assert no captured console errors, with optional `ignorePatterns`
- `expectNoRequest`: assert no captured browser request matched `method` plus `path`, `pathTemplate`, `url`, `urlContains`, or `urlPattern`; use it after the invalid/cancelled/blocked interaction and set `waitMs` when delayed requests are possible
- `expectNoRequestFailures`: assert no captured browser request failures, with optional `ignorePatterns`
- `expectNoFailedResponses`: assert no captured HTTP 4xx/5xx responses, with optional `ignorePatterns`

When `results.json` contains runtime issues but no matching runtime disposition step proves zero unignored issues, `generate_defects.py` emits an undispositioned-runtime finding and `generate_next_probes.py` recommends the focused `expectNo...` probe to add next. Do not treat these findings as proof of product failure until they are mapped to a requirement or reproduced by a focused runtime check.
`apply_next_probes.py` can safely apply these runtime disposition recommendations without extra flags. When a runtime issue is run-level and has no mapped requirement/test yet, it creates a `R-runtime-issue-disposition` matrix row and a focused runtime test so the next cycle can audit the probe normally.
- `dismissIfPresent`: click optional onboarding/modals/overlays if present, without failing when absent
- `screenshot`: capture full-page or locator screenshot

Locator fields accepted by generic locator steps: `selector`, `text`, `role` plus `name`, `label`, `placeholder`, or `testId`.

Optional overlay example:

```json
{
  "action": "dismissIfPresent",
  "id": "T-ui-dismiss-onboarding",
  "testIds": ["T-ui"],
  "requirementIds": ["R-ui"],
  "locators": [
    { "role": "button", "name": "Skip" },
    { "selector": "[aria-label='Close']" }
  ],
  "evidenceType": "ui_interaction",
  "proves": "Optional onboarding overlay was dismissed if it was present."
}
```

Clickability example:

```json
{
  "action": "expectClickable",
  "id": "T-ui-save-clickable",
  "testIds": ["T-ui"],
  "requirementIds": ["R-ui"],
  "role": "button",
  "name": "Save",
  "evidenceType": "ui_interaction",
  "proves": "The Save button is visible and receives pointer events before the workflow clicks it."
}
```

Click-to-response example:

```json
{
  "action": "clickAndWaitForResponse",
  "id": "T-save-click-response",
  "testIds": ["T-save"],
  "requirementIds": ["R-save"],
  "role": "button",
  "name": "Save",
  "method": "POST",
  "responseUrlContains": "/api/v1/settings",
  "expectStatus": 200,
  "captureBody": true,
  "evidenceType": "ui_to_api",
  "proves": "Clicking Save triggers the settings API and it returns a successful response."
}
```

`clickAndWaitForResponse` accepts the same locator fields as `click`, plus response matching fields: `responseUrl`, `responsePath`, `responsePathTemplate`, `responseUrlContains`, `responseUrlPattern`, `urlContains`, `urlPattern`, `method` or `responseMethod`, and optional `matchStatus`. Use `expectStatus`, `expectResponseTextContains`, `expectJson`, `extractJson`, `captureRequestBody`, and `captureBody` to turn the captured request/response pair into auditable evidence.
Use `expectResponseHeader`, `expectResponseHeaderContains`, `expectResponseHeaderMatches`, or `extractResponseHeader` when the click must prove trace ids, cache behavior, content type, auth-dependent headers, or another response-header contract.

## API And Polling Steps

`api` supports GET/POST/PATCH/PUT/DELETE through Playwright's browser request context. `pollApi` uses the same fields and repeats the request until the status/body assertions pass or the poll timeout is reached. `cleanupApi` uses the same request fields for teardown and is intended to run after mutating test flows.

```json
{
  "action": "api",
  "id": "T2-api-create",
  "testIds": ["T2"],
  "requirementIds": ["R2"],
  "method": "POST",
  "path": "/api/v1/items",
  "headers": { "content-type": "application/json" },
  "json": { "name": "qa-probe" },
  "expectStatus": 200,
  "expectJson": {
    "success": true,
    "data.status": { "op": "contains", "value": "created" }
  },
  "captureBody": true,
  "evidenceType": "api_response",
  "proves": "The create endpoint returns success and a created status."
}
```

API fields:

- `method`: Defaults to `GET`.
- `pathTemplate`: Optional path string with runtime placeholders such as `/api/v1/items/{id}`.
- `headers`: Step-level headers.
- `json`: JSON request body. Auth-like keys such as `password`, `token`, `api_key`, or `cookie` must use env/runtime references.
- `body`: Raw body string or object. Object bodies follow the same auth-like key rule as `json`.
- `expectStatus`: Exact HTTP status.
- `expectStatusAny`: Array of allowed HTTP statuses, useful for cleanup endpoints that may return `200`, `202`, `204`, or idempotent `404`.
- `expectResponseTextContains` / `expectResponseTextNotContains`: response-side text assertions. A successful contains check is preserved as `response_text_contains_matched` in the evidence ledger.
- `expectResponseHeader`: Object mapping response header names to exact values or operator expectations such as `{ "op": "exists" }`, `{ "op": "contains", "value": "trace-" }`, or `{ "op": "matches", "value": "^application/json" }`.
- `expectResponseHeaderContains`: Object mapping response header names to required substrings. Values may use runtime refs such as `{ "var": "qa_run_id" }`.
- `expectResponseHeaderMatches`: Object mapping response header names to regular expression strings.
- `extractResponseHeader`: Optional mapping of runtime variable names to response header names, or objects such as `{ "header": "x-trace-id" }`. Use extracted trace/session ids in later API, command, log, or persistence probes.
- `expectRequestTextContains` / `expectRequestTextNotContains`: Assert the submitted request body contains or excludes specific text. Values may use runtime refs such as `{ "var": "qa_marker" }`.
- `expectRequestJson`: Dot-path assertions against the submitted JSON request body. Use it for request-side proof of marker, idempotency key, payload shape, or submitted form values.
- `expectJson`: Dot-path assertions. Values can be exact values or `{ "op": "...", "value": ... }`.
- `expectJsonAny`: Array of alternative dot-path assertion objects; at least one must match. Use this for bounded schema variants, not as a broad fuzzy assertion.
- `extractJson`: Optional mapping of runtime variable names to JSON paths, objects like `{ "path": "data.id", "from": "first" }`, or candidate objects like `{ "paths": ["id", "data.id"] }`.
- `captureRequestBody`: Optional boolean. Store a redacted bounded request body preview and evidence file. Use it only when the request side is part of the proof, such as current-run marker, idempotency key, or submitted form payload.
- `captureResponseHeaders`: Optional boolean. Store redacted response headers in `results.json` and the evidence ledger. Use it only when the response header set itself is part of the proof; sensitive header names are redacted.
- `captureBody`: Store a redacted bounded preview and evidence file.
- `maxRequestBodyChars`: Request preview length. Defaults to `800`.
- `maxBodyChars`: Preview length. Defaults to `800`.
- `pollIntervalMs`: For `pollApi`, delay between attempts. Defaults to `1000`.
- `pollTimeoutMs`: For `pollApi`, total time budget. Defaults to `30000`.
- `maxAttempts`: For `pollApi`, maximum attempt count. Defaults to the timeout/interval budget plus one.
- `alwaysRun`: When `true`, run this step even after a previous step in the same scenario failed.
- `skipIfMissingVars`: For `cleanupApi`, defaults to effectively `true` for missing runtime variables so a failed create step does not turn teardown into a misleading second failure.

Polling example:

```json
{
  "action": "pollApi",
  "id": "T-job-completed",
  "testIds": ["T-job"],
  "requirementIds": ["R-job"],
  "method": "GET",
  "pathTemplate": "/api/v1/jobs/{job_id}",
  "expectStatus": 200,
  "expectJsonAny": [
    { "id": { "var": "job_id" }, "status": "completed" },
    { "data.id": { "var": "job_id" }, "data.status": "completed" },
    { "result.id": { "var": "job_id" }, "result.status": "completed" }
  ],
  "pollIntervalMs": 1000,
  "pollTimeoutMs": 30000,
  "captureBody": true,
  "evidenceType": "api_response",
  "proves": "The same created job eventually reaches completed status."
}
```

Supported JSON operators: `equals`, `exists`, `missing`, `notNull`, `contains`, `notContains`, `matches`, `includes`, `gt`, `gte`, `lt`, `lte`.

Cleanup example:

```json
{
  "action": "cleanupApi",
  "id": "T-item-cleanup",
  "testIds": ["T-item-cleanup"],
  "requirementIds": ["R-item"],
  "method": "DELETE",
  "pathTemplate": "/api/v1/items/{id}",
  "expectStatusAny": [200, 202, 204, 404],
  "alwaysRun": true,
  "skipIfMissingVars": true,
  "evidenceType": "cleanup",
  "proves": "The item created during the test flow is removed or already absent."
}
```

Use cleanup evidence to prove teardown, not to rescue a failed business assertion. If the create step never produced the runtime id, `cleanupApi` is recorded as skipped/inconclusive rather than passed.

## WebSocket Step

Use `websocket` when stream completion is a pass condition.

```json
{
  "action": "websocket",
  "id": "T3-ws-answer-done",
  "testIds": ["T3"],
  "requirementIds": ["R3"],
  "path": "/ws/chat",
  "send": [{ "type": "message", "content": "QA_AIBOX_STREAM_OK" }],
  "expectMessageTextContains": "answer_done",
  "captureMessages": true,
  "evidenceType": "websocket",
  "proves": "The chat stream emits answer_done for the probe turn."
}
```

Fields:

- `url` or `path`: Relative `path` converts `http` to `ws` and `https` to `wss`.
- `send`: String, object, or array of messages to send after open.
- `expectOpen`: Defaults to `true`.
- `expectMessageTextContains`: Require at least one message containing text. A successful check is preserved as `message_text_contains_matched` in the evidence ledger.
- `expectJson`: Require at least one JSON message matching dot-path assertions.
- `extractJson`: Optional mapping of runtime variable names to JSON paths. By default extraction reads from the JSON message matched by `expectJson`; set `{ "path": "...", "from": "first" }` or `{ "path": "...", "from": "last" }` for another message.
- `finishOnMessageTextContains` / `finishOnText`: Finish the probe shortly after a message containing this text. Defaults to `expectMessageTextContains`.
- `finishOnJsonTypes`: Optional array of JSON `type` values that should end the probe after they are received.
- `failOnJsonTypes`: Optional array of JSON `type` values that fail and end the probe. Defaults to `["error"]`; set to `[]` when an error event is expected and asserted separately.
- `finishDelayMs`: Delay before closing after a finish/fail trigger. Defaults to `100`.
- `captureMessages`: Store redacted messages in `evidence/`.
- `waitMs`, `timeoutMs`, `maxMessages`, `maxMessageChars`.

## SSE Step

Use `sse` for EventSource streams.

```json
{
  "action": "sse",
  "id": "T3-sse-done",
  "testIds": ["T3"],
  "requirementIds": ["R3"],
  "path": "/events",
  "expectMessageTextContains": "answer_done",
  "expectJson": {
    "type": "answer_done"
  },
  "captureMessages": true,
  "evidenceType": "sse",
  "proves": "The SSE stream emits answer_done."
}
```

Fields:

- `url` or `path`.
- `eventName`: Optional named SSE event. Defaults to normal `message`.
- `expectOpen`: Defaults to `true`.
- `expectMessageTextContains`: Require at least one event data payload containing text. A successful check is preserved as `message_text_contains_matched` in the evidence ledger.
- `expectJson`: Require at least one JSON event payload matching dot-path assertions.
- `extractJson`: Optional mapping of runtime variable names to JSON paths. By default extraction reads from the JSON event matched by `expectJson`; set `from` to `first` or `last` when needed.
- `finishOnMessageTextContains` / `finishOnText`: Finish the probe shortly after an event containing this text. Defaults to `expectMessageTextContains`.
- `finishOnJsonTypes`: Optional array of JSON `type` values that should end the probe after they are received.
- `failOnJsonTypes`: Optional array of JSON `type` values that fail and end the probe. Defaults to `["error"]`; set to `[]` when an error event is expected and asserted separately.
- `finishDelayMs`: Delay before closing after a finish/fail trigger. Defaults to `100`.
- `captureMessages`: Store redacted event data in `evidence/`.
- `allowErrorEventAfterMessage`: Defaults to `true` because many finite SSE probes close after emitting the target message.
- `waitMs`, `timeoutMs`, `maxMessages`, `maxMessageChars`.

## Command Step

Use `command` for read-only logs, database verification through existing project helpers, process checks, or service probes. Prefer project-approved helper scripts and ORM-backed commands when the repo has data-access rules.

```json
{
  "action": "command",
  "id": "T4-db-completed",
  "testIds": ["T4"],
  "requirementIds": ["R4"],
  "command": ["python3", "scripts/check_turn_status.py", "--turn-id", "qa-turn"],
  "expectExitCode": 0,
  "expectStdoutJson": {
    "status": "completed",
    "message_count": { "op": "gte", "value": 2 }
  },
  "extractStdoutJson": {
    "turn_id": "turn_id"
  },
  "captureStdout": true,
  "evidenceType": "command",
  "proves": "The persisted turn status is completed."
}
```

Fields:

- `command` or `cmd`: Array form with shell execution disabled is required by default. String form and `shell: true` are rejected by `validate_plan.py` unless `--allow-unsafe-command` is explicit. That flag cannot override the secret boundary: commands that read, export, upload, overwrite, or otherwise mutate secret files remain validation errors.
- `cwd`, `env`, `timeoutMs`. When `run_qa_cycle.py --project-root <repo>` is supplied, command steps without `cwd` execute from that project root; relative `cwd`, `requiredFiles`, `requiredDirectories`, and `requiredPaths` are validated from the project root or explicit command `cwd`. Without `--project-root`, they resolve from the plan/run directory. Auth-like `env` keys such as `TOKEN`, `API_KEY`, or `PASSWORD` must use env/runtime references.
- `expectExitCode`: Defaults to `0`.
- `expectStdoutContains` / `expectStderrContains`: stdout/stderr text assertions. A successful stdout contains check is preserved as `stdout_contains_matched` in the evidence ledger.
- `expectStdoutJson`: Dot-path assertions against stdout parsed as JSON. Prefer this for read-only persistence helpers that can output structured state.
- `expectStdoutJsonAny`: Array of alternative stdout JSON assertion objects; at least one must match.
- `extractStdoutJson`: Optional mapping of runtime variable names to stdout JSON paths so later probes can verify the same persisted object.
- `captureStdout` / `captureStderr`: Defaults to `true` when output exists.

## Evidence Mapping

When not using `run_qa_cycle.py`, run the manual sequence. Command steps require the exact passed plan-audit summary at runner execution time:

```bash
python3 scripts/validate_plan.py --plan <run-dir>/test-plan.json --matrix <run-dir>/test-matrix.json --summary <run-dir>/plan-audit-summary.json
node scripts/playwright_probe.mjs --plan <run-dir>/test-plan.json --plan-audit-summary <run-dir>/plan-audit-summary.json
python3 scripts/ledger_from_probe.py --matrix <run-dir>/test-matrix.json --results <run-dir>/results.json --out <run-dir>/evidence-ledger.json
python3 scripts/audit_evidence.py --matrix <run-dir>/test-matrix.json --results <run-dir>/results.json --ledger <run-dir>/evidence-ledger.json --summary <run-dir>/audit-summary.json
```

Do not mark a test `Passed` only because a scenario is `passed`. The final status must come from the evidence ledger and audit.
