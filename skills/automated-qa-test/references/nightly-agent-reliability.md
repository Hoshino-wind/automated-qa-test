# Nightly Agent Reliability Contract

The nightly workflow is an offline maintenance gate for the Agent runtime. It
does not test a production service and its reports are explicitly marked
`not_evidence=true`; they cannot authorize a QA pass for a product run.

## Schedule and isolation

`.github/workflows/nightly-agent-reliability.yml` runs every day at 18:23 UTC
(02:23 Asia/Shanghai) and can also be started with `workflow_dispatch`.
Concurrent runs for the same ref are serialized without cancelling the older
run. Jobs have bounded timeouts, use read-only repository permissions, require
no secrets, and retain diagnostics for 14 days.

The workflow installs the lockfile dependencies and the Playwright-pinned
Chromium build. It never calls a real target service.

## Capability-aware matrix

`scripts/nightly_agent_matrix.py` validates required entrypoints before
emitting the GitHub Actions matrix:

- `full-regression`: the complete deterministic non-browser regression.
- `chromium-regression`: the complete regression with the real local Chromium
  hit-test/backtest fixtures enabled.
- `fault-injection`: deterministic runtime boundary failures.

The matrix also knows the historical browser-policy, component-surface, and
component-resilience benchmark entrypoint names. These targets are enabled only
when the matching script exists in the checked-out commit. Missing optional
entrypoints are recorded under `unsupported_optional_targets`; absence is never
reported as coverage.

Commands are argv arrays in the matrix artifact for auditability. The workflow
dispatches explicit checked-in target ids and does not evaluate the command
field as arbitrary shell input.

Generate the current definition locally:

```bash
python3 skills/automated-qa-test/scripts/nightly_agent_matrix.py \
  --repo-root . \
  --out artifacts/nightly/matrix-definition.json
```

## Fault scenarios

`scripts/nightly_fault_injection.py` exercises only temporary files and child
processes:

- `timeout`: a stage deadline terminates the process group and returns the
  stable timeout boundary.
- `output-limit-and-truncation`: excess output is counted before termination;
  the bounded tail is labeled truncated and the command cannot succeed.
- `lease-conflict`: a second writer is rejected and the first lease is
  preserved.
- `process-crash`: a non-zero child exit is propagated rather than normalized
  to success.
- `corrupt-lease`: malformed lease bytes block acquisition and remain
  untouched for diagnosis.

Run the complete suite or selected cases:

```bash
python3 skills/automated-qa-test/scripts/nightly_fault_injection.py \
  --out artifacts/nightly/fault-injection.json

python3 skills/automated-qa-test/scripts/nightly_fault_injection.py \
  --scenario timeout \
  --scenario lease-conflict
```

The suite exits zero only when every selected boundary is observed. The JSON is
deterministic: it contains stable boundary facts rather than timestamps,
temporary paths, PIDs, or raw process diagnostics.

## Maintenance verification

```bash
python3 -m unittest \
  skills/automated-qa-test/scripts/tests/test_nightly_agent_matrix.py \
  skills/automated-qa-test/scripts/tests/test_nightly_fault_injection.py -v

python3 -m ruff check \
  skills/automated-qa-test/scripts/nightly_agent_matrix.py \
  skills/automated-qa-test/scripts/nightly_fault_injection.py \
  skills/automated-qa-test/scripts/tests/test_nightly_agent_matrix.py \
  skills/automated-qa-test/scripts/tests/test_nightly_fault_injection.py
```
