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

Install the repository-owned runtime dependency:

```bash
npm ci
```

The runner no longer imports Playwright from a personal Codex skill directory. `package-lock.json` is the reproducible dependency source for local use and CI.

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

`qa_agent_loop.py` applies those limits across all iterations; a new iteration does not reset probe or output usage. Verify a completed pass independently:

```bash
python3 skills/automated-qa-test/scripts/verify_run_proof.py \
  --run-dir /path/to/run
```

`qa-run-summary.json` and reports remain projections. The authority chain is `run-events.jsonl`, `run-manifest.json`, the referenced immutable attempt, and the current hash-bound verdict.

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

## Project Adapters

The core is project-agnostic. Optional project knowledge lives in `skills/automated-qa-test/references/adapters/*.json`. Adapter files own detection markers, services, env/config candidates, evidence layers, preflight routing, and probe defaults. No personal checkout path is embedded in the core scripts.

## Architecture Boundaries

`scripts/*.py` remain stable CLI compatibility entrypoints. `scripts/qa_core/contracts` owns artifact paths, runtime JSON Schema validation, evidence fields, and runner-binding rules. `scripts/qa_core/pipeline` owns `CycleOptions`, `CycleContext`, and the uniform stage execution/journaling boundary. `scripts/qa_core/runtime`, `state`, and `proof` own bounded process execution, leases, immutable attempts, event reduction, and proof verification. `scripts/qa_core/tools` and `agent` own strict ToolSpec, proposal, policy, and execution-authorization contracts; model output is a proposal, never an authorization. `CycleRuntime` composes the requirement, preflight, adapter, planning, probe, evidence, and conclusion stages.

Scaffold internals follow the one-way `qa_scaffold/support → intents → modeling → rules → entry` dependency chain while the legacy `scaffold_requirement.py` module keeps its documented imports and CLI. Requirement classification is split into signal collection, conflict disambiguation, and three tag-projection families; requirement-specific evidence mapping plus foundation, resilience, authentication, integrity, advanced, UI-interaction, and runtime point rules use bounded private domain helpers behind their existing public functions. Regression fixtures place code-PR, source-coverage, and Agent-route contracts in dedicated support-only modules, then re-export their stable fixture entries through `contracts` or `agent`; build/release and secret-safety fixtures further dispatch to bounded private subscenario registries without changing the seven-family public fixture contract. `regression_check.py` owns only fixture registration, full-suite phase orchestration, and CLI handling. Architecture tests enforce dependency direction, bounded private family registries, and compatibility exports.

CI runs Ruff `E`, `F`, and `I` checks before compilation and tests. Long requirement/fixture prose is intentionally exempt from `E501`, and test bootstrap modules may import after their explicit local `sys.path` setup; unused imports, dead locals, and import ordering remain blocking errors.

The production-candidate architecture, invariants, SLOs, and held-out protocol are defined in [`CONTEXT.md`](CONTEXT.md) and [`docs/architecture/agent-v2.md`](docs/architecture/agent-v2.md). `agent_eval.py` is a strict evaluator-owned scorer, not proof that a production corpus has been run: production qualification still requires an independently frozen 200-scenario × 3-seed corpus and deterministic baseline.

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

During development, list or target isolated regression groups. Omitting `--group` preserves the complete non-browser regression:

```bash
python3 skills/automated-qa-test/scripts/regression_check.py --list-groups
python3 skills/automated-qa-test/scripts/regression_check.py --group contracts --group evidence
```

CI runs the repository dependency install, compile check, safety suite, Node syntax check, and full non-browser regression.
