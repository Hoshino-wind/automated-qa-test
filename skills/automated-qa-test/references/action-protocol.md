# Durable Action Protocol

This contract separates a planned probe from a durably recorded dispatch. It
applies to the integrated `run_qa_cycle.py` → `playwright_probe.mjs` path and
does not turn model output, scheduler advice, or a report into authorization.

## Artifacts

`action-contracts.json` is derived before dispatch from:

- the exact `test-plan.json` SHA-256;
- the compiled `agent-context.json` SHA-256;
- the passed current `plan-audit-summary.json` SHA-256;
- run id, lease generation, and iteration;
- the canonical default `ToolSpec` registry and per-action ToolSpec hash;
- required and granted authorization capabilities;
- ToolSpec-declared risk, idempotency, and recovery policy;
- the canonical hash of the exact raw step;
- the canonical runtime-reference resolution-policy hash;
- for each `command`, a concrete execution binding covering its deterministic
  working directory, sanitized child-environment hash, resolved executable,
  and direct regular-file argv inputs.

The artifact is strict, canonical-hash-bound, and marked
`not_evidence=true`. Every plan step must have exactly one authorized contract.
Unknown actions, stale plans/audits, unconfirmed or production-like environment
boundaries, missing capabilities, duplicate step identities, unknown fields,
and registry/spec drift fail before probe dispatch. A contract's own canonical
hash and `authorized=true` are not trusted authorization: Python verification
and the Node dispatch boundary independently compare registry hash, action,
version, ToolSpec hash, risk, idempotency, and required capabilities against
the built-in current trusted ToolRegistry, then recompute the policy grant and
authorization hash. Immediately before the probe stage, the Python
orchestrator also issues an ephemeral HMAC authorization ticket over the
current contract, context, plan audit, registry, run, generation, and
iteration. Its key and ticket exist only in that child process environment.
The Node runner consumes and removes them before dispatch. A self-consistent
contract that merely claims an isolated-environment grant therefore cannot
authorize itself.

`action-journal.jsonl` is the append-only dispatch record. Each line contains a
strict event with a contiguous sequence, previous-event hash, canonical event
hash, run/generation/iteration identity, scenario/step/action identity,
ToolSpec hash, invocation hash, deterministic idempotency key, idempotency
class, status, and timezone-aware occurrence time.

## Intent, side effect, commit

For each actual or policy-skipped step, the runner:

1. verifies the raw-step hash, resolves the invocation under the bound policy,
   and recomputes its ToolSpec-bound hash;
2. appends and fsyncs an `intent` with `status=pending`;
3. dispatches the side effect, or applies the explicit skip;
4. appends and fsyncs one matching `commit` with `passed`, `failed`, or
   `skipped`.

A commit must refer to one unresolved earlier intent and match every dispatch
identity field exactly. Intent and commit both carry a structured,
secret-redacted invocation commitment and a derived execution-authorization
hash. That
authorization binds the raw step, resolution policy, run/lease/iteration,
scenario/step/action identity, ToolSpec, contract authorization, and resolved
invocation structure without persisting resolved secret material or a naked
hash of that material. It also binds the ephemeral authorization-ticket hash
and a separate execution-controls hash covering the secret-redacted I/O
structure,
effective command argv, normalized cwd, sanitized child-environment hash,
declared timeout controls, and output limits. The Python verifier
independently recomputes the commitment envelope, idempotency key, contract
authorization, and execution authorization. It also requires current action
coverage and exact agreement with `results.json`; a result row without the
matching committed action, or an extra current commit, fails closed.

## Runtime reference boundary

Runtime reference objects are strict closed unions. Exactly one discriminator
is allowed:

- `{ "env" | "$env": "NAME", "prefix"?: "...", "suffix"?: "...",
  "json"?: boolean }`
- `{ "var" | "$var": "name", "prefix"?: "...", "suffix"?: "...",
  "json"?: boolean }`
- `{ "template" | "$template": "...", "encodeVars"?: boolean,
  "json"?: boolean }`

Aliases cannot be mixed and unknown fields are rejected. A plan, scenario, or
step object can never be replaced wholesale by a reference, and
`scenario.id`, `step.id`, and `step.action` remain static across parsing and
resolution.

The command execution control plane is stricter: `command`, `cmd`, `cwd`,
`shell`, and command `env` reject environment, runtime-variable, and template
reference objects at any depth. Immediately before dispatch, the runner
confirms these fields are byte-for-byte canonically unchanged and reapplies
the current ToolSpec's argv/shell, timeout, output, destructive-command, and
secret-read/exfiltration checks. The command child receives an allowlisted
inherited environment plus static explicit entries, not the runner's full
environment. This closes the
"raw plan safe, resolved command malicious" gap.

Command approval also binds what will execute, rather than only the raw
`argv[0]` string. Contract construction resolves `argv[0]` through the current
allowlisted `PATH`, follows it to a real absolute path, and records a stable
single-link regular-file identity (`device`, `inode`, `size`, nanosecond
mtime, mode, and SHA-256). Existing regular files named directly by argv are
bound the same way; recognized interpreter script operands are mandatory
direct inputs. The integrated orchestrator supplies its canonical probe cwd as
the command base; standalone callers default that base to the plan directory.
Relative `cwd` values and an omitted cwd are resolved against this bound base,
so a later launcher cwd cannot reinterpret them. The
binding SHA enters the per-action authorization hash, the human gate's stable
action projection, and therefore the authorization ticket's contract/action
commitments.

Python re-derives that binding immediately before issuing a ticket. Node
independently uses bigint file metadata, re-derives it before opening the
journal, repeats the check before intent and immediately before spawn, and
spawns the bound executable realpath while replacing bound file argv entries
with their bound realpaths. A changed `PATH`, executable, symlink target,
direct script, or bound child environment therefore fails before a command
side effect; changes already present at Node startup fail before an action
intent exists.

For compatibility, the child allowlist currently retains `PATH`,
`PYTHONPATH`, and `NODE_PATH`, but their exact values are part of the
environment commitment and handoff drift fails closed. This is not a
transitive dependency or process-image attestation: imported modules,
shared libraries, shebang interpreters, dynamically loaded plugins, files
opened by application code, and a replacement in the narrow interval after
the final revalidation and kernel process creation are outside this proof.
Production commands that depend on those surfaces still need an immutable
runtime image or sandbox/mount policy; removing `PYTHONPATH`/`NODE_PATH` from
the inherited allowlist is the preferred stricter deployment profile.

High-risk `api`, `pollApi`, and `cleanupApi` actions apply the same rule to
their network target. `plan.baseUrl` plus step `method`, `url`, and `path` must
produce a literal, absolute, credential-free HTTP(S) URL;
`urlTemplate`/`pathTemplate`, fragments, ambiguous base URLs, browser/context
proxy or base-URL overrides, routing headers, routing launch arguments, and
redirects are forbidden. The Node executor mirrors this check before
reference resolution, revalidates the target immediately before dispatch, and
includes the canonical method/URL plus `max_redirects=0` in execution controls.
Approval of one scheme/host/port/path/method therefore cannot be reused after
an environment-variable, virtual-host, proxy, relative-base, or redirect swap.

For a high-risk network step, runtime references are forbidden in the body,
JSON, path, method, and non-credential headers because changing them can
change the affected object or operation. Only an explicit credential-header
allowlist (`Authorization`, `Cookie`, API-key and auth-token forms) may contain
a dynamic reference; its source identity remains bound even though its secret
value is not persisted. Credential rotation is not target authorization. This
is a static request-identity guarantee, not DNS or network-route attestation;
production still needs evaluator-controlled egress policy to contain DNS
rebinding and compromised upstream infrastructure.

For actions below that high-risk boundary, environment-backed header, cookie,
and request-body values remain supported.
Resolved values exist only in memory for dispatch. Before hashing any durable
invocation or I/O commitment, every dynamic reference is replaced by a
structured marker containing its reference kind, alias, source name, location,
and raw-reference hash plus `[REDACTED]`. The exact raw-step hash separately
preserves the authorized reference syntax. Neither the secret value nor a
direct hash of it enters the journal, so a four-digit OTP cannot become an
offline enumeration oracle. Known resolved secret values are also redacted
from result previews and text artifacts. Environment variables consumed as
data-plane references are removed from the environment inherited by command
child processes.

The Node runner holds an `O_NOFOLLOW` regular single-link file handle for the
journal and fsyncs every append. The Python preflight/verifier independently
reject partial lines, duplicate JSON keys, non-finite values, unknown fields,
oversized files/lines, symlink/hardlink inputs, broken sequences, orphaned or
duplicate commits, invalid hashes, and mismatched contracts.

## Crash recovery

An unresolved intent means the previous process may have crossed the side
effect boundary:

- If its ToolSpec declares `idempotent=true`, recovery may append a matching
  `commit` with `status=abandoned_safe`, then replay the invocation with the
  same deterministic idempotency key.
- If it is non-idempotent, automatic replay is forbidden and preflight returns
  `action_reconciliation_required`. A human or external system must establish
  the real side-effect state before a new action can be authorized.

The idempotency key binds `run_id`, lease generation, iteration, scenario id,
step id, action, canonical invocation hash, and execution authorization. A
caller cannot obtain a new key merely by relabeling recovery metadata, and an
old generation's key cannot authorize replay in a new lease generation.

## Proof and non-execution modes

`run_qa_cycle.py` preflights an existing journal before invoking Node, verifies
it again after probe completion, binds the verified journal and contracts into
the immutable attempt, and requires the proof verifier to close that graph.
Action records prove dispatch lineage; they are not product assertions and do
not replace evidence audit or the deterministic verdict.

`--skip-probe` dispatches no actions, issues no action contracts, records zero
action spans, and is handoff-only. Historical `results.json` must not be
projected as a current action record, and the cycle cannot claim `PASS`.

## Trust boundary

- Planner and Critic may propose an action but cannot set its ToolSpec,
  idempotency, risk, or authorization.
- Scheduler may suggest a batch, including a parallel batch, but cannot dispatch
  it.
- HITL approval may satisfy a declared human control requirement, but the
  approved decision is one-shot and still does not bypass the current
  ToolSpec/policy/action contract. For a human-gated intent, any existing
  current intent blocks automatic redispatch even when the ToolSpec is
  idempotent; an operator must reconcile it, and a new attempt requires an
  explicit human execution epoch plus a new approval/checkpoint chain.
- P2 release admission is a release-scoped qualification result, never an
  action authorization.

Every runtime dispatch must therefore remain bound to the current lease,
context, state, plan, budget, ToolSpec, and deterministic policy decision.
