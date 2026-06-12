# 自动化 QA-Test Charter Template

Use this template to convert a requirement, issue, or PR into a testable plan.

## Source

- Requirement source:
- Branch/PR/issue:
- Target environment:
- Test account/role:
- Out-of-scope areas:

## Requirement Extraction

| ID | Requirement Point | Source Evidence | Test Mapping | Status |
| --- | --- | --- | --- | --- |
| R1 |  | Quote/link exact source line | T1 | Pending |

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
| Persistence/display rules |  |
| Error and empty states |  |
| Responsive/interaction risks |  |

## Test Matrix

| ID | Requirement | Test Type | Steps/Probe | Expected Result | Required Evidence | Actual Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | R1 | logic |  |  | screenshot/log/API |  | Pending |

Allowed statuses: Passed, Failed, Blocked, Untested, Inconclusive.

## Coverage Gaps

- Blocked:
- Not safe to test:
- Needs user-provided access/data:
- Deferred regression scope:
- Requirement points without evidence:
