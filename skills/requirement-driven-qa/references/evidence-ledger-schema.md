# Evidence Ledger Schema

Use an evidence ledger whenever a QA run needs strict accuracy. The ledger is the only place where final requirement statuses should be recorded.

## Status Rules

Allowed statuses:

- `Passed`: direct current-run evidence proves the requirement.
- `Failed`: current-run evidence contradicts expected behavior.
- `Blocked`: a concrete blocker prevented testing.
- `Untested`: no execution was attempted within the run.
- `Inconclusive`: evidence exists but does not prove pass or fail.

Do not invent data. Do not mark `Passed` without evidence.

## Minimal Ledger

```json
{
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
      "proves": "The created agent is visible in the UI list."
    },
    {
      "id": "E2",
      "type": "api_response",
      "url": "/api/v1/agents",
      "status_code": 200,
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

Test entries:

- `id`
- `requirement_ids`
- `type`
- `expected`
- `status`
- `evidence_ids`

Evidence entries:

- `id`
- `type`
- one locator field such as `path`, `url`, `file`, `log_ref`, or `value`
- `proves`

## Audit Expectations

Run `scripts/audit_evidence.py` before final reporting:

```bash
python3 scripts/audit_evidence.py --matrix <run-dir>/test-matrix.json --ledger <run-dir>/evidence-ledger.json --summary <run-dir>/audit-summary.json
```

The audit fails when:

- a requirement has no mapped tests;
- a matrix requirement or test is missing from the evidence ledger;
- a requirement has an invalid status;
- a `Passed` requirement has no evidence;
- a `Passed` test has no evidence;
- a requirement references a missing test;
- a requirement or test references missing evidence;
- screenshot/file evidence points to a missing local file;
- a non-passed item lacks a note explaining blocker, failure, or uncertainty.
