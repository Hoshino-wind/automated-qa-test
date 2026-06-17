# QA Agent Loop Contract

Use this reference before running, interpreting, or modifying `scripts/qa_agent_loop.py`.

## Contents

- Runtime contract
- Artifact currentness
- Next-probe safety
- Failure category routing
- Loop-control projections
- Self-convergence
- Gap-driven repair
- Handoff reliability

## Runtime Contract

`scripts/qa_agent_loop.py` runs a bounded QA/backtest loop over one run directory. It initializes or resumes a run, executes `run_qa_cycle.py`, previews safe next-probe applications, applies them only when allowed, snapshots every iteration, writes machine-readable `next_action`, writes top-level `loop_control`, and writes human-readable `qa-agent-handoff.md`.

It must write `qa-agent-summary.json` and `qa-agent-handoff.md` even when initialization fails before a runnable cycle exists. Use `--summary` when supplied; otherwise use `<run-dir>/qa-agent-summary.json` or the fallback summary path under the requested output directory.

The loop may pass `--skip-report` through to `run_qa_cycle.py` for verdict-only maintenance runs. It stops on pass, blocker, no safe follow-up, failure, or max iterations.

## Artifact Currentness

Treat `qa-run-summary.json`, `qa-verdict.json`, `qa-cycle-error.json`, `service-preflight.json`, `service-runtime.json`, `adapter-context.json`, `adapter-probes.json`, `business-model.json`, `oracle-model.json`, `qa-metrics.json`, `closeout-candidates.json`, `semantic-artifacts-summary.json`, `defects.json`, `results.json`, `evidence-ledger.json`, `audit-summary.json`, `plan-audit-summary.json`, `requirement-coverage.json`, and next-probe preview/application artifacts as current only when produced or applied in the same iteration.

Stale, malformed, directory-shaped, or non-object artifacts are historical or unreadable evidence only. Do not let stale pass verdicts, old reports, old results, old ledgers, old semantic planning artifacts, or stale next-probe previews drive the current action.

Iteration snapshots must replace stale file/directory shape mismatches and record copy errors in `snapshot_details` instead of crashing the loop.

## Next-Probe Safety

Only auto-apply next probes previewed inside the same loop and hash-bound with `expected_next_probes_sha256`.

Applying an existing `next-probes.json` before the first cycle requires explicit `--apply-existing-next-probes`. Resume commands emitted after max-iteration stops must include `--apply-existing-next-probes` plus `--expected-next-probes-sha256` so a replaced `next-probes.json` stops with `repreview_next_probes`.

When `--apply-existing-next-probes` is explicit but `next-probes.json` is missing, directory-shaped, or not a regular file, stop before `run_qa_cycle.py` with `repreview_next_probes` and a `next_probes` input artifact error.

When manual resume passes `--apply-existing-next-probes` without an explicit expected hash, recover the latest previewed hash from `qa-agent-summary.json`; if no hash can be recovered, stop before `run_qa_cycle.py` with `repreview_next_probes` and `missing_expected_next_probes_sha256`.

If a current cycle writes `qa-verdict.json` with `can_claim_pass=true`, skip next-probe preview and stop on `report_pass`. Optional follow-up preview failures must never override a pass-claimable audited verdict.

If max iterations stop the loop after a safe preview, `resume_with_more_iterations` must include a concrete command with a larger `--max-iterations`, the original strict/runtime flags, any custom `--summary` path, `--apply-existing-next-probes`, and the previewed `next-probes.json` hash.

## Failure Category Routing

Every non-pass loop state needs `failure_analysis` with stable `category`, `blocking_layer`, `source`, `reason_codes`, `operator_hint`, and `confidence`. Do not collapse blockers into a generic non-pass report when a more specific category is known.

`next_action` must be selected from the failure category even when no safe follow-up probe is available:

- `environment_boundary_unconfirmed` -> `confirm_environment_boundary`
- `requirement_or_adapter_blocker` or follow-up input gaps -> `request_authorization_or_inputs`
- `evidence_pipeline_failure` -> `repair_evidence_pipeline`
- `product_defect` -> `report_product_defect`
- `setup_environment_blocker` -> `report_setup_blocker`
- `planning_coverage_blocker` -> `report_planning_blocker`
- input artifact integrity -> `fix_input_artifacts` or `fix_next_probe_inputs`

If environment-boundary reason codes are mixed with product defects, runtime gaps, or safe strategy follow-ups, prioritize `confirm_environment_boundary` before treating observed behavior as a product conclusion.

Previewed safe follow-ups are not enough to continue automatically. Auto-apply only when `next_action.automatable=true`, which is allowed only for `runtime_evidence_gap`, `untested_coverage_gap`, `strategy_coverage_gap`, `requirement_or_adapter_blocker`, or generic `non_pass_verdict`, and only when the previewed probes are safe, concrete, and not mixed with actionable blocked follow-ups.

If a preview contains both safe applied probes and actionable skipped probes requiring authorization, safe payloads, selectors, helpers, or lineage repair, stop with `request_authorization_or_inputs` instead of partially auto-continuing.

When runtime preflight blocks with a concrete `start_plan` and `--start-missing-services` was not authorized, `next_action` must expose `retry_with_service_start`, the compact start plan, resume command args, and service-start authorization requirement.

When `qa-verdict.json` contains `input_artifact_errors`, expose `fix_input_artifacts` with exact artifact names/paths. When next-probe preview fails with `input_artifact_errors`, expose `fix_next_probe_inputs` with exact artifact names/paths.

## Loop-Control Projections

Read `loop_control.agent_route_model` first as the single routing contract. Then verify `orchestration_state`, `recommended_next_steps`, `human_action_required`, and `evidence_health` as projections.

`agent_route_model` names the mode, primary action, human request type, first recommended step, first evidence gap, shared confirmation fields, missing inputs, recommended flags, manual revision targets, and next-step/gap ids that the other loop-control projections must match.

`orchestration_state` is the compact routing projection for external orchestrators. It names modes such as `auto_continue`, `await_confirmation`, `await_authorization`, `repair_inputs`, `repair_evidence_pipeline`, `await_iteration_budget`, `manual_revision_or_report`, `report`, and `report_pass`.

`evidence_health` is the compact safety projection. Its route fields and top-level status are derived from `agent_route_model`; its flags and counts summarize artifact health, audit errors, runtime issues, defects, source coverage, strategy gaps, environment-boundary confirmation needs, service blockers, adapter blockers, cycle errors, and current-run evidence.

`human_action_required` is the compact checklist for external orchestrators and humans. It states whether the stop needs service-start authorization, environment/data-boundary confirmation, input artifact repair, more-iteration approval, manual plan revision, artifact inspection, or report-only handling.

## Self-Convergence

Treat a preview with only non-actionable duplicate/equivalent skipped follow-ups, or a preview whose `next-probes.json` hash already appeared earlier in the same loop/resume binding, as `report_no_new_progress`.

In no-new-progress states, `loop_control.no_new_progress`, `loop_control.non_actionable_followups`, and `loop_control.repeated_next_probes` tell external orchestrators not to keep iterating unless a human changes the plan or requirement.

`recommended_next_steps` must put report/manual revision before evidence-gap repair suggestions, and `qa-agent-handoff.md` must render the same no-new-progress reason for human handoff.

## Gap-Driven Repair

Read `loop_control.evidence_gap_plan` after `loop_control.evidence_health`. It ranks repairable evidence gaps such as input/artifact integrity, audit errors, environment/data-boundary confirmation, service preflight/runtime blockers, adapter-probe blockers, cycle helper errors, requirement-source coverage, runtime disposition, strategy coverage, blocked follow-up inputs, and missing current-run evidence.

Each gap carries a resolved `operation` with `kind`, `route_mode`, and any authorization, confirmation, repair, or recommended flag fields. `agent_route_model`, `recommended_next_steps`, `orchestration_state`, and `human_action_required` must project this operation instead of re-deriving it independently.

Gap-driven projections surface top gap ids/actions, compact `details`, required confirmation fields, missing inputs, manual revision targets, recommended flags, authorization/repair booleans, and step-level resolved `evidence_artifacts` paths/hashes.

## Handoff Reliability

`loop_control.evidence_artifacts` should resolve `next_action.evidence` names into run-dir-bound paths with `exists`, `kind`, `sha256`, and `size_bytes`.

`loop_control.current_artifacts` and iteration snapshots should include current setup/context/error evidence such as `service-preflight.json`, `service-runtime.json`, `adapter-context.json`, `adapter-probes.json`, `business-model.json`, `oracle-model.json`, `qa-metrics.json`, `closeout-candidates.json`, `semantic-artifacts-summary.json`, and `qa-cycle-error.json` when those artifacts exist or were expected in the cycle.

`qa-agent-handoff.md` should render `agent_route_model` before `orchestration_state`, then render the same paths and hashes so operators can see the current routing mode, first repair/confirmation/probe step, exact artifacts to read next, and drift signals without parsing JSON first.
