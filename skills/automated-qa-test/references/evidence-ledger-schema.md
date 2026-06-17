# Evidence Ledger Schema

Use an evidence ledger whenever a QA/backtest run needs strict accuracy. The ledger is the only place where final requirement statuses should be recorded.

## Status Rules

Allowed statuses:

- `Passed`: direct current-run evidence proves the requirement.
- `Failed`: current-run evidence contradicts expected behavior.
- `Blocked`: a concrete blocker prevented testing.
- `Untested`: no execution was attempted within the run.
- `Inconclusive`: evidence exists but does not prove pass or fail.

Do not invent data. Do not mark `Passed` without evidence. Do not use a failed/error evidence item to prove a passed requirement.

## Minimal Ledger

```json
{
  "schema_version": 2,
  "runtime_summary": {
    "probe_status": "passed",
    "console_errors": 0,
    "console_warnings": 0,
    "failed_responses": 0,
    "request_failures": 0
  },
  "requirements": [
    {
      "id": "R1",
      "source": "issue #123 line 4",
      "text": "User can create an agent and see it in the list.",
      "test_ids": ["T1"],
      "status": "Passed",
      "evidence_ids": ["E1", "E2"],
      "notes": "Verified via UI screenshot and API 200 response."
    }
  ],
  "tests": [
    {
      "id": "T1",
      "requirement_ids": ["R1"],
      "type": "ui+api",
      "expected": "Agent is created, visible in list, and API returns 200.",
      "status": "Passed",
      "evidence_ids": ["E1", "E2"]
    }
  ],
  "evidence": [
    {
      "id": "E1",
      "type": "screenshot",
      "path": "screenshots/agent-created.png",
      "current_run": true,
      "assertions": ["The created agent name is visible in the list."],
      "proves": "The created agent is visible in the UI list."
    },
    {
      "id": "E2",
      "type": "api_response",
      "url": "/api/v1/agents",
      "status_code": 200,
      "checked_json": { "success": true },
      "assertions": ["HTTP status observed: 200", "JSON success matched true"],
      "current_run": true,
      "proves": "The agents API returned successfully after creation."
    }
  ]
}
```

## Required Fields

Requirement entries:

- `id`
- `source`
- `text`
- `test_ids`
- `status`
- `evidence_ids`
- `notes` for `Failed`, `Blocked`, `Untested`, or `Inconclusive`

Test entries:

- `id`
- `requirement_ids`
- `type`
- `expected`
- `status`
- `evidence_ids`
- `notes` for `Failed`, `Blocked`, `Untested`, or `Inconclusive`

Evidence entries:

- `id`
- `type`
- one locator field: `path`, `url`, `file`, `log_ref`, or `value`
- `proves`

Recommended evidence fields:

- `current_run`: `true` when generated during this run. Evidence cited by a `Passed` requirement or test must set this to `true`; historical evidence can provide context but cannot prove a pass. When `audit_evidence.py` receives `--results` and `results.json.startedAt` is available, file-backed current-run evidence must not predate that run start.
- `path`: for `screenshot` evidence, this must point to a readable PNG/JPEG image with nonzero dimensions, not a placeholder text file or stale path.
- `generated_by`: script or manual source.
- `scenario_id`, `step_id`, `action`, `status`, `test_ids`, `requirement_ids`: probe lineage fields used by audit, defect generation, and reporting. Evidence cited by a `Passed` requirement or test must declare the matching requirement or test lineage when it comes from the bundled runner; manual evidence without lineage is allowed but remains audit-warning context.
- `assertions`: concrete observed assertions, not vague commentary.
- `status_code`, `checked_json`: for API evidence.
- `messages_seen`, `checked_json`, `path`: for WebSocket or SSE evidence.
- `exit_code`, `path`: for command/log/DB-helper evidence.
- `body_path`, `request_body_path`, `messages_path`, `stdout_path`, `stderr_path`: explicit captured text artifact paths. When present, audit re-reads these files to confirm related text-match fields and checked JSON path/value pairs.
- `extracted_json` with `extracted_json_paths`, and `extracted_stdout_json` with `extracted_stdout_json_paths`: extracted runtime variables and their source JSON paths. When the source artifact exists, audit re-reads it and confirms the extracted value came from the recorded path.
- `response_headers`, `checked_response_headers`, `extracted_response_headers`, `extracted_response_header_names`: response header evidence. When the captured header map exists, audit confirms checked and extracted header values match it case-insensitively.
- `message_text_contains_matched`: returned WebSocket/SSE message text contained a required marker or phrase.
- `response_text_contains_matched`: returned API/UI-to-API response text contained a required marker or phrase.
- `stdout_contains_matched`: command/log/persistence helper stdout contained a required terminal status such as `completed`.
- `error`: only when the evidence demonstrates a failed or inconclusive result.

## Audit Expectations

Before ledger/reporting, run requirement-source coverage when `requirement.md` exists:

```bash
python3 scripts/audit_requirement_coverage.py \
  --requirement <run-dir>/requirement.md \
  --matrix <run-dir>/test-matrix.json \
  --out <run-dir>/requirement-coverage.json
```

`requirement-coverage.json` is not proof that the feature passed. It only proves that source behavior points were represented in the matrix. Unmapped source units must block broad pass claims through `qa-verdict.json`.

Run `scripts/audit_evidence.py` before final reporting:

```bash
python3 scripts/audit_evidence.py \
  --matrix <run-dir>/test-matrix.json \
  --results <run-dir>/results.json \
  --ledger <run-dir>/evidence-ledger.json \
  --summary <run-dir>/audit-summary.json
```

Use `--strict-runtime` when console errors, failed requests, or request failures should fail an otherwise all-passed run unless explicitly mapped to a failed/non-passed requirement.

`audit-summary.json` records the audited ledger/matrix/results paths, their sha256 hashes, and sha256 hashes for referenced evidence artifact files. If `evidence-ledger.json`, `test-matrix.json`, `results.json`, or a referenced evidence artifact changes after the audit, rerun `scripts/audit_evidence.py` before generating `qa-verdict.json`; the final verdict blocks pass claims when the audit summary is unbound, stale, from another run, when matrix audit binding is missing, when evidence artifact hashes are missing or mismatched, when the audit-bound `results.json` is omitted, when `results.json.artifactDir` points outside the current run artifact directory, when `plan-audit-summary.json` fails validation, when `requirement-coverage.json` has unmapped source units, when `defects.json` contains findings or a summary/findings count mismatch, or when existing sibling `defects.json`, `requirement-coverage.json`, `plan-audit-summary.json`, `service-preflight.json`, `service-runtime.json`, `adapter-probes.json`, or `adapter-context.json` artifacts are left out of verdict generation or replaced by same-named artifacts from another run.

For a run intended to support a real pass claim, generate the final verdict with `--require-environment-boundary` and a confirmed `adapter-context.json`. The verdict blocks `can_claim_pass=true` when:

- `adapter-context.json` is missing;
- `environment_boundary.runtime_mode` is unconfirmed;
- `environment_boundary.data_boundary_status` is unconfirmed.

The audit fails when:

- a requirement has no mapped tests;
- a matrix requirement or test is missing from the evidence ledger;
- a requirement has an invalid status;
- a `Passed` requirement maps to any test whose status is not `Passed`;
- a `Passed` requirement or test has no evidence;
- a `Passed` requirement or test references failed/error evidence;
- a `Passed` requirement or test references evidence whose `requirement_ids` / `test_ids` lineage belongs to a different requirement or test;
- a requirement references a missing test;
- a requirement or test references missing evidence;
- screenshot/file evidence points to a missing local file;
- screenshot evidence points to an unreadable, non-PNG/JPEG, or zero-dimension image artifact;
- a captured text artifact contradicts `message_text_contains_matched`, `response_text_contains_matched`, `request_text_contains_matched`, `stdout_contains_matched`, `stderr_contains_matched`, or the corresponding `*_not_contains_matched` field;
- a captured JSON artifact cannot be parsed or contradicts `checked_json`, `checked_request_json`, or `checked_stdout_json`;
- a captured JSON artifact contradicts `extracted_json` / `extracted_stdout_json`, or an extracted value lacks its recorded source path;
- captured response headers contradict `checked_response_headers` or `extracted_response_headers`;
- evidence lacks `proves` or any locator field;
- API, WebSocket, SSE, or command evidence lacks type-specific assertion signals;
- a `Passed` stream/WebSocket/SSE test has no WebSocket/SSE evidence or captured message signal;
- a `Passed` API or click-to-response test has no API/click-to-response evidence;
- a `Passed` persistence/database test has no persistence/log/API evidence;
- a `Passed` marker, stale-seed, fallback-avoidance, or seed-avoidance claim lacks returned marker evidence such as `message_text_contains_matched`, `response_text_contains_matched`, returned stdout text, or checked returned JSON containing the actual marker value; generic current-run evidence is checked through `current_run=true`, assertion signals, and freshness when `results.json.startedAt` exists;
- a `Passed` `answer_done`, terminal, or `completed` claim lacks terminal-status evidence;
- UI interaction evidence should include assertions from `expectClickable` or equivalent hit-test/actionability evidence when clickability is the claim;
- a non-passed item lacks a note explaining blocker, failure, or uncertainty;
- `TODO` placeholder text remains in final ledger requirement/evidence text;
- secret-like values such as JWTs, bearer tokens, API keys, session tokens, or auth tokens appear in the ledger.

## Defect Generation

After ledger audit, run:

```bash
python3 scripts/generate_defects.py \
  --matrix <run-dir>/test-matrix.json \
  --results <run-dir>/results.json \
  --ledger <run-dir>/evidence-ledger.json \
  --out <run-dir>/defects.json
```

`defects.json` is derived evidence, not a replacement for the ledger. It groups failed tests into defect findings with severity, affected layers, expected behavior, actual evidence, inference, repro steps, and evidence ids. Keep inference labeled; do not claim a root cause unless logs or code evidence prove it.

## Next-Probe Recommendations

After generating defects, run:

```bash
python3 scripts/generate_next_probes.py \
  --defects <run-dir>/defects.json \
  --results <run-dir>/results.json \
  --ledger <run-dir>/evidence-ledger.json \
  --out <run-dir>/next-probes.json
```

`next-probes.json` is a recommended diagnostic queue for the next turn. It is not current-run evidence and must not change current requirement status by itself. Each recommendation should include a layer, objective, reason, required inputs, and a plan-step hint that can be reviewed or adapted before execution. Same-object variables used by follow-up probes should come from the current results step matched by scenario id, step id/action, and requirement/test lineage; do not let a sibling scenario that reuses the same step id supply `session_id`, `turn_id`, job id, or trace id.

Only apply a recommendation automatically when it can be mapped back to a requirement or test, either directly through `source_test_id` / `requirement_ids` or through defect/evidence lineage. Run-level runtime disposition probes may create their own runtime matrix row. Any other lineage-free recommendation must stay as a handoff item until it is repaired into a mapped probe.

## Marker And Stream Evidence

For AI/chat backtests, never pass a run only because a prompt marker exists somewhere in the transcript. The marker must appear in the returned answer or stream output, and stream completion should be separately proven when completion is a requirement.

Strong evidence examples:

- WebSocket message contains `answer_done`.
- Returned answer contains a unique marker that was requested and is not only present in user input.
- Persistence evidence shows the turn/session reached the required terminal status, such as `completed`.

Weak evidence examples:

- The UI shows fallback copy but no stream event was observed.
- A screenshot contains the user prompt marker only.
- The HTTP request returned 200 but the database/log state is failed or missing.
