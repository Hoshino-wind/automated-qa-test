# 自动化 QA-Test Report Template

# <Feature / Requirement Name> QA Report

## 1. Summary

- Result:
- Highest severity:
- Requirement source:
- Environment:
- Adapter context: `adapter-context.json` path, detected adapter, service status, data boundary.
- Adapter probes: `adapter-probes.json` path, whether probes were applied, proposed steps, and blocked adapter layers.
- Runtime preflight: `service-preflight.json` path, runnable flag, blockers, and start candidates.
- Service runtime: `service-runtime.json` path when startup was used, startup mode, started services, ready services, failed services, and log paths.
- Requirement source coverage: `requirement-coverage.json` path, covered source units, and unmapped source units.
- Final verdict: `qa-verdict.json` path, verdict value, `can_claim_pass`, artifact-binding status, and any failure/blocker/gap reasons.
- Test time:
- Evidence integrity: Current-run evidence only; no fabricated data; unverified items marked Blocked, Untested, or Inconclusive.
- Evidence audit: Pass/Fail, audit-summary path, remaining errors if any.

## Final Verdict

- Verdict:
- Can claim pass:
- Statement:

Populate this section from `qa-verdict.json`. If `can_claim_pass=false`, if the verdict is stale/unbound from the current ledger, audit summary, results, matrix, evidence artifact hashes, `results.json.artifactDir`, or current-run sibling artifacts, or if later conclusion artifacts such as `plan-audit-summary.json`, `defects.json` findings or summary mismatches, `requirement-coverage.json`, setup blockers, adapter blockers, or environment boundaries contradict the pass claim, do not phrase the report as a passed backtest even when some individual probes passed.

## Requirement Source Coverage

Populate this section from `requirement-coverage.json`. If any source unit is unmapped, list it as a coverage gap and do not run or phrase broad product probes as complete.

## 2. Scope

Before the scope table, state the runtime mode and data boundary from `adapter-context.json` when available. Do not conclude pass/fail until this boundary is explicit.

| Area | Included | Notes |
| --- | --- | --- |
| Feature logic | Yes/No |  |
| Interaction | Yes/No |  |
| Data/API flow | Yes/No |  |
| Stream/WebSocket/SSE | Yes/No |  |
| Persistence/log verification | Yes/No |  |
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

Populate this section from `defects.json` when generated. If adding manual findings, keep them evidence-backed and label inference separately.

Only include observed defects. Do not invent defect counts or impact estimates. If impact is inferred, label it as an inference.

## 6. Runtime Errors

- Console:
- Network/API:
- Request failures:
- WebSocket/SSE errors:
- Backend logs:

### Runtime Disposition

| Evidence | Raw Issue | Disposition | Remaining Risk |
| --- | --- | --- | --- |

If console warnings, request failures, or HTTP failures are ignored, explain why they are accepted and cite the evidence row that proves no unignored issue remains.

## 7. Next Probes

| Priority | Layer | Objective | Reason | Required Inputs |
| --- | --- | --- | --- | --- |

Populate this section from `next-probes.json` when generated. These are proposed follow-up probes, not current-run pass/fail evidence.
Also include blocked entries from `adapter-probes.json` when adapter synthesis could not safely create stream, session, or persistence probes.
When `service-preflight.json` contains blockers, include those blockers as setup probes before product probes.

## 8. Data Flow

- Input data:
- API calls:
- Stream events and terminal events:
- Extracted runtime variables:
- Persistence:
- Command/log stdout evidence:
- UI display:
- Downstream effects:
- Evidence gaps:

## 9. Evidence Layering

Use this section when a flow can appear successful in one layer while failing in another.

| Layer | Expected Signal | Observed Signal | Status | Evidence |
| --- | --- | --- | --- | --- |
| UI/catalog/seed |  |  |  |  |
| Frontend rendered reply/fallback |  |  |  |  |
| Real stream/API completion |  |  |  |  |
| Persistence/log state |  |  |  |  |

Do not merge these rows into one pass unless every in-scope layer is directly proven.

## 10. Interaction Notes

- Loading/disabled states:
- Validation:
- Modal/navigation:
- Empty/error states:
- Responsive:

## 11. Gaps

- Blocked:
- Untested:
- Inconclusive:
- Requirement points without direct evidence:
- Risk accepted:

This section is mandatory. If no gaps remain, write `None identified in the audited scope` and cite the audit summary.

## 12. Screenshots

Embed or link screenshots here. When sending to Feishu/Word/Google Docs, embed the images in the document artifact rather than leaving only local paths.
