# Automated QA Test

[![CI](https://github.com/Hoshino-wind/automated-qa-test/actions/workflows/ci.yml/badge.svg)](https://github.com/Hoshino-wind/automated-qa-test/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[简体中文](README.zh-CN.md)

![Automated QA Test — evidence-bound QA agent](docs/social-preview.png)

Turn one product requirement into executable probes, current-run evidence, and a verdict that refuses to pass when the proof is incomplete.

```text
requirement → test matrix → browser / API / stream / command probes
            → evidence ledger → proof verifier → verdict + report
```

## The 15-second version

AI-generated test reports can sound complete even when the underlying behavior was never observed. Automated QA Test treats every `Passed` claim as an evidence-integrity problem:

- requirements are compiled into traceable test cases and executable probes;
- evidence is bound to the current run, source requirement, test, step, and content hash;
- a bounded Agent loop may investigate further, but model output is never treated as execution authorization;
- stale files, missing coverage, unsafe commands, unresolved runtime errors, and competing writers fail closed;
- an independent read-only verifier closes the state → manifest → immutable attempt → current-input proof graph.

The result is a requirement-driven Codex skill for evidence-bound web, API, stream, persistence, and command QA—not a report generator that grades its own prose.

## Requirements

- Python 3.12+
- Node.js 20+
- npm
- Chrome or a Playwright-managed Chromium browser for browser probes

Install the pinned runtime dependencies in an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install "cryptography>=47,<48"
npm ci
```

`pyproject.toml` owns the Python dependency contract and `package-lock.json`
owns the Node dependency graph used locally and in CI. The runner no longer
imports Playwright from a personal Codex skill directory.

## Install The Skill

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/automated-qa-test "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Invoke it as `$automated-qa-test` with a requirement, issue, PR, or bug report.

## Canonical Workflow

Initialize a run with an explicit environment and data boundary:

```bash
python3 skills/automated-qa-test/scripts/init_qa_artifact.py \
  --requirement-file /path/to/requirement.md \
  --base-url http://127.0.0.1:3000 \
  --runtime-mode test \
  --data-boundary-status "isolated test database; no production data"
```

Review the generated matrix and plan, then run the complete cycle:

```bash
python3 skills/automated-qa-test/scripts/run_qa_cycle.py \
  --run-dir /path/to/run \
  --preflight-runtime \
  --strict-runtime
```

`run_qa_cycle.py` is the normal execution entry. It refreshes semantic artifacts, checks requirement coverage, validates and SHA-256-binds the plan, executes probes, builds and audits the ledger, generates defects/next probes, writes `qa-verdict.json`, and renders the report.

Command steps cannot run through `playwright_probe.mjs` unless `--plan-audit-summary` points to a passed summary bound to the exact plan hash. Shell-string commands and `shell: true` are rejected by default; use array commands with shell execution disabled. `--allow-unsafe-command` can relax that ordinary shell boundary, but cannot override secret-file reads, exports, uploads, writes, or other secret mutations. Generated outputs stay under `--run-dir` by default, and directory-shaped output targets are preserved and rejected.

## Proof-Carrying Runtime

Every cycle and outer Agent loop now has one wall-clock/probe/output budget and one logical writer. The cycle holds a generation-fenced filesystem lease, records a hash-chained event journal, commits current outputs into an immutable attempt, then publishes `Passed` only after a separate read-only proof verifier closes the state → manifest → attempt → current-input graph. A stale file, changed parent input, uncommitted verdict, old attempt, corrupt event, or competing writer therefore fails closed.

Before any probe action is dispatched, the orchestrator compiles a current
repository/context snapshot and derives `action-contracts.json` from the
validated plan and the canonical `ToolSpec` registry. The runner then appends an
`intent` before each side effect and a matching `commit` to
`action-journal.jsonl` afterwards. Recovery may replay only a ToolSpec-declared
idempotent action with the same deterministic key; an uncertain non-idempotent
action requires human reconciliation. See
[`action-protocol.md`](skills/automated-qa-test/references/action-protocol.md).

The default limits are 1,800 seconds per run, 300 seconds per stage, 500 probes, 16 MiB of child output, and a 2-second TERM-to-KILL grace period. Override them explicitly with:

```bash
python3 skills/automated-qa-test/scripts/run_qa_cycle.py \
  --run-dir /path/to/run \
  --total-timeout-seconds 1800 \
  --stage-timeout-seconds 300 \
  --max-probes 500 \
  --max-output-bytes 16777216 \
  --termination-grace-seconds 2
```

`qa_agent_loop.py` applies those limits across all iterations; a new iteration does not reset probe or output usage. Verify a terminal outcome independently:

```bash
python3 skills/automated-qa-test/scripts/verify_run_proof.py \
  --run-dir /path/to/run
```

The verifier reports `proof_valid` separately from `can_claim_pass`.
Proof-backed failure and cancellation/timeout observations remain non-PASS;
only a verified success can authorize `can_claim_pass=true`.

`qa-run-summary.json` and reports remain projections. The authority chain is `run-events.jsonl`, `run-manifest.json`, the referenced immutable attempt, and the current hash-bound verdict.

If the cycle starts a managed service, ordinary stages preserve a final
10-second and 64-KiB `RunBudget` reserve for the real stop/cleanup stage.
State transitions and stage/action/cleanup spans are separately hash chained in
the run state and `agent-trace.jsonl`; the proof verifier requires their
sequence, command hashes, attempt, and current context bindings to agree.

`--skip-probe` is a planning/blocker handoff mode. It dispatches no action,
issues no action contracts, and can never produce a valid `PASS`.

## Fail-Closed Pass Rules

`can_claim_pass=true` requires all of the following by default:

- schema major version 2 for plan, matrix, results, and ledger;
- mapped requirement-source coverage;
- a passed, hash-bound plan audit;
- current `results.json` bound through the evidence audit;
- no unresolved runtime, setup, adapter, defect, or pipeline gaps;
- a confirmed runtime mode and data boundary in `adapter-context.json`.

The `--allow-unconfirmed-environment`, `--allow-unvalidated-plan`, and `--allow-missing-requirement-coverage` options are explicit exceptions for planning or partial runs. Their output must not be represented as a real-environment pass.

For custom probes without `results.json`, provide a provenance manifest to both audit and verdict generation:

```json
{
  "schema_version": 1,
  "mode": "manual",
  "operator": "qa-user",
  "observed_at": "2026-07-22T12:00:00+08:00",
  "statement": "Evidence was captured from the declared isolated test environment.",
  "evidence_ids": ["E1", "E2"]
}
```

```bash
python3 skills/automated-qa-test/scripts/audit_evidence.py \
  --matrix /path/to/run/test-matrix.json \
  --ledger /path/to/run/evidence-ledger.json \
  --manual-evidence-manifest /path/to/run/manual-evidence-manifest.json \
  --summary /path/to/run/audit-summary.json
```

Manual evidence mode is explicit and hash-bound; handwritten `current_run`, `assertions`, or `proves` fields alone cannot unlock a pass.

## Agent Control And Release Gates

The repository includes strict control-plane CLIs, but deliberately separates
suggestion, release admission, and runtime authorization:

- `compile_agent_context.py` creates the repository/requirement/Adapter snapshot
  used for plan and proof currentness.
- `agent_critic_cli.py` and `agent_schedule_cli.py` rank or batch candidates.
  Their outputs are suggestions with `not_authorization=true`; a parallel batch
  is not permission to execute it.
- `human_control_cli.py` manages Ed25519-approved HITL and confirmed knowledge.
  Production journal mode additionally requires an independently signed,
  unexpired anti-rollback checkpoint that exactly covers the current journal;
  uncovered tails fail closed and production consumption requires a refreshed
  checkpoint before resume. High-risk runtime dispatch adds a second refreshed
  checkpoint and durable one-shot redemption; recovery requires an explicit
  reconciled execution epoch. Knowledge is always `not_evidence=true` and its
  exact current query snapshot is hash-bound into ContextSnapshot.
- `agent_slo_report.py --run-dir ...` recomputes proof-backed production SLOs.
  `--trace` produces analysis only and is never production qualification.
- `agent_eval.py --production` verifies an independently signed evaluator
  registration for the frozen corpus, candidate, baseline, thresholds, budgets,
  and SLO input set.
- `agent_release_admission.py` recomputes both production gates and may issue a
  P2 release-scoped admission. It never authorizes a runtime tool or action.

No bundled fixture or local self-test establishes real production
qualification. That requires externally controlled evaluator/approval
authorities, a signed held-out corpus registration, and proof-backed production
runs. P2 parallel or multi-Agent runtime execution is not automatically enabled
by an admission report.

Detailed contracts:

- [tracing and SLO](skills/automated-qa-test/references/agent-observability.md)
- [HITL and confirmed knowledge](skills/automated-qa-test/references/human-control.md)
- [scheduler/critic trust boundary](docs/architecture/scheduler-critic-trust-boundary.md)
- [production evaluation and P2 release admission](skills/automated-qa-test/references/agent-release-admission.md)
- [nightly reliability and fault injection](skills/automated-qa-test/references/nightly-agent-reliability.md)

## Project Adapters

The core is project-agnostic. Optional project knowledge lives in `skills/automated-qa-test/references/adapters/*.json`. Adapter files own detection markers, services, env/config candidates, evidence layers, preflight routing, and probe defaults. No personal checkout path is embedded in the core scripts. Validate every new definition before relying on detection:

```bash
python3 skills/automated-qa-test/scripts/adapter_registry.py \
  --definition skills/automated-qa-test/references/adapters/example.json \
  --project-root /path/to/project \
  --out /tmp/example-adapter-onboarding.json
```

The onboarding report is conformance metadata (`not_evidence=true`,
`not_authorization=true`), not a product QA result. See
[`project-adapters.md`](skills/automated-qa-test/references/project-adapters.md).

## Architecture Boundaries

`scripts/*.py` remain stable CLI compatibility entrypoints. `scripts/qa_core/contracts` owns artifact paths, runtime JSON Schema validation, evidence fields, and runner-binding rules. `scripts/qa_core/pipeline` owns `CycleOptions`, `CycleContext`, and the uniform stage execution/journaling boundary. `scripts/qa_core/runtime`, `state`, `observability`, and `proof` own bounded process execution, durable action intents, leases, immutable attempts, event/trace reduction, and proof verification. `scripts/qa_core/context`, `hitl`, and `knowledge` own current context plus externally anchored human-control state. `scripts/qa_core/tools`, `agent`, `planning`, and `scheduling` own strict ToolSpec, proposal, policy, Planner/Diagnostician/Critic, and suggestion-only scheduling contracts; the caller, not the model, supplies the exact model identity and evidence-reference allowlist, and the Diagnostician can reference only current plan hypotheses/probes plus allowed trace observations. Model output is a proposal with `not_authorization=true`, never an authorization. `qa_eval` owns strict evaluator registration and release admission. `CycleRuntime` composes the requirement, preflight, adapter, planning, probe, evidence, cleanup, and conclusion stages.

Scaffold internals follow the one-way `qa_scaffold/support → intents → modeling → rules → entry` dependency chain while the legacy `scaffold_requirement.py` module keeps its documented imports and CLI. Requirement classification is split into signal collection, conflict disambiguation, and three tag-projection families; requirement-specific evidence mapping plus foundation, resilience, authentication, integrity, advanced, UI-interaction, and runtime point rules use bounded private domain helpers behind their existing public functions. Regression fixtures place code-PR, source-coverage, and Agent-route contracts in dedicated support-only modules, then re-export their stable fixture entries through `contracts` or `agent`; build/release and secret-safety fixtures further dispatch to bounded private subscenario registries without changing the seven-family public fixture contract. `regression_check.py` owns only fixture registration, full-suite phase orchestration, and CLI handling. Architecture tests enforce dependency direction, bounded private family registries, and compatibility exports.

CI runs Ruff `E`, `F`, and `I` checks before compilation and tests. Long requirement/fixture prose is intentionally exempt from `E501`, and test bootstrap modules may import after their explicit local `sys.path` setup; unused imports, dead locals, and import ordering remain blocking errors.

The production-candidate architecture, invariants, SLOs, and held-out protocol are defined in [`CONTEXT.md`](CONTEXT.md) and [`docs/architecture/agent-v2.md`](docs/architecture/agent-v2.md). `agent_eval.py` is a strict evaluator-owned scorer, not proof that a production corpus has been run: production qualification still requires an independently frozen and signed 200-scenario × 3-seed corpus, deterministic baseline, and proof-backed SLO roots.

## Main Artifacts

The complete run includes the requirement, business/oracle models, charter, matrix, plan, environment context, preflight/runtime records, requirement and plan audits, results, evidence ledger, audit summary, defects, next probes, verdict, agent handoff, and report. Planning models and metrics are explicitly marked `not_evidence=true`; only current-run audited evidence can support a pass.

Allowed statuses are `Passed`, `Failed`, `Blocked`, `Untested`, and `Inconclusive`.

## Development Verification

Fast safety and syntax checks:

```bash
npm test
python3 -m compileall -q skills/automated-qa-test/scripts
```

`npm test` includes the independent context-adversarial corpus in `references/modeling-adversarial-cases.json`. It checks static security terminology, 422 validation UX, revocation invariants, and browser scroll-state restoration separately from the in-file gold corpus.

Full maintenance regression:

```bash
npm run test:regression
python3 skills/automated-qa-test/scripts/regression_check.py --with-browser
```

Generate the capability-aware nightly matrix and run its deterministic fault
injection locally:

```bash
python3 skills/automated-qa-test/scripts/nightly_agent_matrix.py \
  --repo-root . \
  --out /tmp/nightly-agent-matrix.json
python3 skills/automated-qa-test/scripts/nightly_fault_injection.py \
  --out /tmp/nightly-fault-injection.json
```

During development, list or target isolated regression groups. Omitting `--group` preserves the complete non-browser regression:

```bash
python3 skills/automated-qa-test/scripts/regression_check.py --list-groups
python3 skills/automated-qa-test/scripts/regression_check.py --group contracts --group evidence
```

CI runs the repository dependency install, compile check, safety suite, Node syntax check, and full non-browser regression.
