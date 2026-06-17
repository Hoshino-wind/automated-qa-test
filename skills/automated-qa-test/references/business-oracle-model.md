# Business and Oracle Model Artifacts

Use these artifacts to make QA runs understand business intent before execution. They are not evidence.

## Artifacts

- `business-model.json`: planning context extracted from the requirement. It records actors, entities, entry points, API paths, workflows, state transitions, business rules, risk assumptions, and the agent-team handoff contract.
- `oracle-model.json`: the pass/fail oracle for each requirement. It maps requirement ids to tests, required evidence layers, weak signals to avoid, blocked-until inputs, and the pass rule.
- `qa-metrics.json`: run-planning metrics such as requirement count, test count, actor/entity/workflow counts, blocked tests, coverage gaps, evidence-layer counts, automation readiness, and manual intervention points.
- `closeout-candidates.json`: human-confirmation handoff candidates for later memory, prompt, skill, or project-process updates. It must never write durable knowledge by itself.
- `semantic-artifacts-summary.json`: refresh summary for the semantic artifact set. It records current source bindings, warnings, blockers, and compact counts from the regenerated artifacts.

## Rules

- Treat the business model as a hypothesis from the requirement source. Correct it when the repo, UI, API, or user clarifies the actual business semantics.
- Treat the oracle model as the test contract. A requirement can pass only when its mapped tests pass with current-run, lineage-bound evidence for every required layer.
- Keep weak signals visible. Examples: screenshots without actionability, status-only API checks, request-only prompt markers, fallback text, seed data, and handwritten terminal-state claims.
- Keep closeout candidates as candidates. Persist them to memory, prompts, DB rows, docs, or skill files only after explicit human confirmation.
- If a business rule is unclear, mark the related oracle item blocked instead of inventing expected behavior.
- Each semantic artifact must carry `not_evidence=true`, an `artifact_role`, and `source_bindings` for its current upstream sources. Missing, stale, or mismatched bindings mean the artifact is not renderable planning context.
- Regenerate semantic artifacts with `scripts/refresh_semantic_artifacts.py` after changing `requirement.md`, `test-matrix.json`, `test-plan.json`, or applying next probes. `run_qa_cycle.py` does this before validation.
- `generate_report.py` must suppress the Business Intent Model, Oracle Model, QA Metrics, and Closeout Candidates sections when semantic bindings fail. It may render only the binding guard issues; do not copy stale semantic content into the report as context.
- Never use semantic artifact counts to fit or repair product evidence. If metrics, oracle rows, or closeout candidates disagree with the current matrix/plan, refresh them or block the report section.

## Agent Team Boundary

- Business Agent output: requirement source, clarified actors/entities/workflows, acceptance criteria, business rules, non-goals, environment/data boundary assumptions.
- QA/Test Agent input: the above plus source-bound `business-model.json`, `oracle-model.json`, `qa-metrics.json`, `closeout-candidates.json`, `semantic-artifacts-summary.json`, `test-matrix.json`, and `test-plan.json`.
- QA/Test Agent output: current-run evidence, defects, verdict, report, metrics, and closeout candidates.
- Final pass authority: `qa-verdict.json` with `can_claim_pass=true`, not the business model, oracle model, metrics, or report prose alone.
