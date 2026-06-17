# 自动化 QA-Test Charter Template

Use this template to convert a requirement, issue, or PR into a testable plan.

## Source

- Requirement source:
- Branch/PR/issue:
- Target environment:
- Data boundary: local/test/staging/prod; mock/seed/real data:
- Test account/role:
- Out-of-scope areas:

## Requirement Extraction

| ID | Requirement Point | Source Evidence | Test Mapping | Status |
| --- | --- | --- | --- | --- |
| R1 |  | Quote/link exact source line | T1 | Untested |

Do not leave a requirement point unmapped. If it is out of scope, blocked, or unsafe to test, state that explicitly in `Test Mapping`.

## Behavior Model

| Area | Notes |
| --- | --- |
| User goal |  |
| Actors and permissions |  |
| Entry points |  |
| State transitions |  |
| Input validation |  |
| API/data dependencies |  |
| Stream/WebSocket/SSE dependencies |  |
| Persistence/display rules |  |
| Strong pass signals |  |
| Weak/misleading signals |  |
| Error and empty states |  |
| Responsive/interaction risks |  |

## Test Matrix

| ID | Requirement | Test Type | Steps/Probe | Expected Result | Required Evidence | Actual Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | R1 | logic |  |  | screenshot/log/API |  | Untested |

Allowed statuses: Passed, Failed, Blocked, Untested, Inconclusive.

## Evidence Layer Plan

Use this table when one workflow crosses multiple layers.

| Requirement | Layer | Strong Evidence Needed | Weak Evidence To Avoid | Probe |
| --- | --- | --- | --- | --- |
| R1 | UI |  |  | Playwright screenshot/assertion |
| R1 | API/stream |  |  | API/WebSocket/SSE probe |
| R1 | Persistence/log |  |  | Read-only command/helper |

## Coverage Gaps

- Blocked:
- Not safe to test:
- Needs user-provided credential/data:
- Deferred regression scope:
- Requirement points without evidence:
