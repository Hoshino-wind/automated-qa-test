# 自动化 QA-Test Report Template

# <Feature / Requirement Name> QA Report

## 1. Summary

- Result:
- Highest severity:
- Requirement source:
- Environment:
- Test time:
- Evidence integrity: Current-run evidence only; no fabricated data; unverified items marked Blocked, Untested, or Inconclusive.
- Evidence audit: Pass/Fail, audit-summary path, remaining errors if any.

## 2. Scope

| Area | Included | Notes |
| --- | --- | --- |
| Feature logic | Yes/No |  |
| Interaction | Yes/No |  |
| Data/API flow | Yes/No |  |
| Permissions | Yes/No |  |
| Error handling | Yes/No |  |
| Responsive | Yes/No |  |

## 3. Requirement Coverage

| Requirement | Source Evidence | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |

Allowed statuses: Passed, Failed, Blocked, Untested, Inconclusive.

Populate this section from `evidence-ledger.json`, not from memory or unsupported inference.

## 4. Test Results

| Test | Requirement | Type | Status | Expected | Actual | Evidence |
| --- | --- | --- | --- | --- | --- | --- |

## 5. Defects

| Severity | Title | Repro Steps | Expected | Actual | Evidence |
| --- | --- | --- | --- | --- | --- |

Only include observed defects. Do not invent defect counts or impact estimates. If impact is inferred, label it as an inference.

## 6. Runtime Errors

- Console:
- Network/API:
- Backend logs:

## 7. Data Flow

- Input data:
- API calls:
- Persistence:
- UI display:
- Downstream effects:
- Evidence gaps:

## 8. Interaction Notes

- Loading/disabled states:
- Validation:
- Modal/navigation:
- Empty/error states:
- Responsive:

## 9. Gaps

- Blocked:
- Untested:
- Inconclusive:
- Requirement points without direct evidence:
- Risk accepted:

This section is mandatory. If no gaps remain, write `None identified in the audited scope` and cite the audit summary.

## 10. Screenshots

Embed or link screenshots here. When sending to Feishu/Word/Google Docs, embed the images in the document artifact rather than leaving only local paths.
