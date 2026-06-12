# Playwright Probe Plan Schema

`scripts/playwright_probe.mjs` runs a small JSON plan. The plan is intentionally generic so each requirement can define its own pages, checks, and interactions.

## Minimal Plan

```json
{
  "baseUrl": "http://127.0.0.1:3000",
  "artifactDir": "/tmp/automated-qa-test/run",
  "scenarios": [
    {
      "id": "main-flow",
      "title": "Main requirement flow",
      "steps": [
        { "action": "goto", "path": "/" },
        { "action": "expectText", "text": "Dashboard" },
        { "action": "screenshot", "name": "dashboard" }
      ]
    }
  ]
}
```

## Top-Level Fields

- `baseUrl`: Base URL for relative `path` values.
- `artifactDir`: Optional output directory. Defaults to the directory containing the plan.
- `viewport`: Optional `{ "width": 1440, "height": 980 }`.
- `headless`: Optional boolean. Defaults to `true`.
- `scenarios`: Required array of scenarios.

## Scenario Fields

- `id`: Stable scenario id, lowercase/dash preferred.
- `title`: Human-readable title.
- `steps`: Ordered browser actions and assertions.

## Supported Steps

- `goto`: `{ "action": "goto", "path": "/route" }` or `{ "action": "goto", "url": "https://..." }`
- `clickText`: click visible text, `{ "action": "clickText", "text": "Submit" }`
- `clickRole`: click by role/name, `{ "action": "clickRole", "role": "button", "name": "Submit" }`
- `fillLabel`: fill by label, `{ "action": "fillLabel", "label": "Email", "value": "test@example.com" }`
- `fillPlaceholder`: fill by placeholder, `{ "action": "fillPlaceholder", "placeholder": "Search", "value": "abc" }`
- `press`: press a key on the page, `{ "action": "press", "key": "Enter" }`
- `wait`: fixed short wait, `{ "action": "wait", "ms": 1000 }`
- `expectText`: assert visible text, `{ "action": "expectText", "text": "Saved" }`
- `expectUrlContains`: assert current URL contains text, `{ "action": "expectUrlContains", "text": "/success" }`
- `screenshot`: capture full-page screenshot, `{ "action": "screenshot", "name": "after-save" }`
- `api`: fetch an endpoint from the browser context, `{ "action": "api", "path": "/api/health", "expectStatus": 200 }`

Each step may include:

- `id`: stable step/test id.
- `requirementIds`: requirement ids this step supports.
- `evidenceType`: intended evidence category, such as `screenshot`, `api_response`, `ui_text`, or `network`.
- `proves`: the exact claim this step can prove if it passes.

API steps may also include:

- `expectResponseTextContains`: fail if the response text does not contain this string.
- `expectJson`: object of dot-path checks, for example `{ "data.status": "ready" }`.
- `captureBody`: boolean to store a bounded response preview.
- `maxBodyChars`: maximum body preview length, default 500.

Use this runner for smoke and regression probes. For complex drag/drop, canvas, file upload, auth, or domain-specific assertions, write focused Playwright code in the repo or extend the plan for that run.

## Evidence Mapping

After running the plan, map executed steps into `evidence-ledger.json`.

- Screenshot steps can become `screenshot` evidence entries.
- API steps can become `api_response` evidence entries.
- Failed steps can support `Failed` or `Inconclusive`, but not `Passed`.
- Console and failed network entries must be summarized in the final report and considered when deciding whether related requirements are passed.

Do not mark a test `Passed` only because the scenario status is `passed`; map the scenario output to the specific requirement and evidence first.

## Strict Example

```json
{
  "action": "api",
  "id": "T2-api-list",
  "requirementIds": ["R2"],
  "path": "/api/v1/items",
  "expectStatus": 200,
  "expectJson": { "success": true },
  "captureBody": true,
  "evidenceType": "api_response",
  "proves": "The list endpoint returns successfully with success=true."
}
```
