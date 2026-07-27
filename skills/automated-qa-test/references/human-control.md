# Human control and knowledge contract

`human_control_cli.py` is a fail-closed control-plane boundary. It records
human decisions and curated knowledge; it never executes an approved action and
none of its artifacts are QA evidence.

## Trust root

Production approval receipts use detached Ed25519 signatures. The Agent and CLI
receive only an explicit `authority -> key_id -> public key` allowlist. They do
not accept, load, log, or persist private keys.

Every receipt must contain:

- `algorithm: "Ed25519"`;
- an allowlisted `authority` and `key_id` pair;
- a canonical base64url Ed25519 `signature`;
- operation, operator, subject hash, human decision, approval time, receipt id,
  and external receipt hash.

The signature covers the canonical JSON object containing every receipt field
except `signature`. Unknown fields, unsigned receipts, unknown authorities,
unknown keys, key/authority substitution, non-canonical signatures, and
tampered payloads are rejected. Receipt verification also runs while replaying
the append-only journal, not only at mutation time.

CLI trust configuration is public data:

```json
{
  "schema_version": 1,
  "authorities": [
    {
      "authority": "corp-approval-service",
      "keys": [
        {
          "key_id": "approval-key-2026-07",
          "algorithm": "Ed25519",
          "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
        }
      ]
    }
  ],
  "checkpoint_authorities": [
    {
      "authority": "journal-checkpoint-service",
      "keys": [
        {
          "key_id": "checkpoint-key-2026-07",
          "algorithm": "Ed25519",
          "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
        }
      ]
    }
  ]
}
```

The parser rejects private-key material and any unknown trust-config fields.
`cryptography` with Ed25519 support is a runtime dependency; if it is missing,
receipt verification fails closed.

## HITL currentness and consumption

A request and its decision bind all of:

- `run_id`;
- positive `lease_generation`;
- `context_sha256`;
- `action_sha256`;
- `policy_sha256`;
- `authorization_sha256`.

Every request must allow both `approved` and `rejected`. Decision recording and
resume compare all bindings exactly. A stale lease takeover, policy change,
authorization change, context change, or action change requires a new request.

An `approved` decision is not itself reusable execution authority. The executor
must call `hitl-consume` with a unique `consumption_id`. The store appends a
`hitl_decision_consumed` event atomically; every later consumption attempt
fails, including an identical retry. Rejected, missing, stale, or expired
decisions cannot be consumed.

Production consumption is deliberately two phase. The first `hitl-consume`
call durably appends the consumption event but returns
`checkpoint_refresh_required`, so it is not permission to dispatch the action.
The external authority must observe that append and publish a new checkpoint.
Only a later `hitl-resume` that verifies exact checkpoint coverage may confirm
`status: consumed`. A downstream dispatcher must bind its own idempotency key
to the returned `consumption_id`; neither a decision nor an unanchored consume
error is an execution grant.

Runtime currentness uses the store's injected timezone-aware clock. CLI runtime
commands use the system UTC clock and expose no caller-controlled `--at`
override. Historical inspection is available through journal projection APIs,
not through runtime resume/query.

## Runtime high-risk gate

`run_qa_cycle.py` can make HITL mandatory for every action whose trusted
ToolSpec classifies it as `high`:

```bash
python3 scripts/run_qa_cycle.py \
  --run-dir <run-dir> \
  --human-control-store <hitl-store> \
  --human-control-trust-config <public-trust.json> \
  --human-control-journal-mode production \
  --human-control-checkpoint <signed-checkpoint.json> \
  --human-execution-epoch 1
```

The runtime uses three independently checkpointed invocations:

1. From a complete checkpoint, append the exact hash-bound request and hand
   off without dispatch.
2. After an externally signed decision and a fresh full checkpoint, append the
   one-shot consumption and hand off again.
3. After a fresh checkpoint covering that consumption, append
   `human_dispatch_redeemed` atomically. Only the invocation whose transaction
   reports that new append may dispatch. The append immediately makes the
   supplied checkpoint stale, so every later invocation must refresh and then
   observes `already_redeemed`.

The stable authorization binds the run and lease, ContextSnapshot, plan,
plan audit, ToolSpec registry, complete normalized action set, high-risk action
set, policy, and positive `human_execution_epoch`. Trace/state iteration is not
part of the request identity, so normal handoff sequence advancement cannot
orphan the approval. The final execution iteration is instead derived from the
execution-intent hash.

`human-authorization.json` is written before the final contracts. Its exact
file hash is bound into `action-contracts.json`, the ephemeral HMAC dispatch
ticket, every action intent/commit event, the immutable attempt, run state, and
the proof graph. Local-test mode, a stale or partial checkpoint, missing,
expired, rejected, wrong-binding, or previously redeemed approval cannot
dispatch. Human-gated action recovery overrides normal same-key idempotent
recovery: any prior current action intent requires reconciliation and is never
automatically redispatched.

Redemption deliberately occurs before the side effect. A crash in that gap
dead-ends the unchanged execution intent instead of guessing whether the side
effect happened. After an operator reconciles the target and immutable
attempt/action journal, they may explicitly increment
`--human-execution-epoch`; this creates a new request and requires the complete
decision/checkpoint flow again. The runtime never increments the epoch
automatically.

The one-shot guarantee is relative to the current externally anchored HITL
history. A coordinated rollback of both journal and checkpoint cannot be
detected by a local process. Exactly-once behavior across such rollback or
crash boundaries additionally requires an external monotonic CAS/lease or an
idempotent target.

`verify_human_authorization_artifact` verifies the exact run-local derived gate
artifact and its checkpoint-tail/redemption commitments. It does **not**
independently reverify the Ed25519 decision or checkpoint signature because
the artifact contains hashes of the trust inputs, not their complete signed
objects. Runtime authenticity comes from `evaluate_high_risk_human_gate`
replaying those signed inputs, followed by exact file-hash binding and the
internal dispatch ticket. Proof output therefore labels this
`runtime_gate_artifact_binding` and sets
`external_signature_reverified=false`; standalone/offline authenticity would
require committing the full public trust configuration and signed checkpoint
and rerunning their external verifier.

## Knowledge time and scope

Knowledge remains `not_evidence: true`. Its time chain is:

`provenance.observed_at <= candidate.proposed_at <= receipt.approved_at <= entry.committed_at`

`committed_at` and `revoked_at` come from the store's trusted clock. A knowledge
entry that is already expired at commit is rejected. Runtime query filters
future, expired, revoked, and superseded entries using that same clock.

Scope matching is exact after canonicalization. Extra caller dimensions are not
treated as authorization and a missing entry dimension is not an implicit
wildcard. Cross-environment or cross-tenant reuse therefore requires a separate
explicitly scoped entry.

When `run_qa_cycle.py` receives `--knowledge-store`,
`--knowledge-trust-config`, one or more exact `--knowledge-scope` values, and
the corresponding journal/checkpoint mode, `compile_agent_context.py` embeds a
deterministic query snapshot into ContextSnapshot. The snapshot binds the
journal path/content/projection/terminal hashes, public-trust file and semantic
hashes, checkpoint, query-currentness rules, entries, and its own hash. It is
always `not_evidence=true`; it informs planning but cannot prove a product
claim. Proof binds the attempt-time snapshot without claiming that a mutable
store is still current later. Candidate-model memory and this runtime
KnowledgeStore are separate trust roots; no equality or transitive authority
is implied.

## Persistence boundary

Events are strict JSON, monotonically sequenced, and hash chained. Snapshots are
derived projections and never the source of truth. Symlink/hard-link output
aliases and writes inside a protected store root are rejected.

### Signed anti-rollback checkpoint

A local hash chain detects mutation but cannot by itself detect deletion of a
valid tail. Production mode therefore requires an independently issued
Ed25519-signed checkpoint. Its signature covers:

- `journal_kind` (`hitl` or `knowledge`);
- `journal_path_sha256`, a domain-separated digest of the real absolute,
  normalized event-journal path;
- non-negative `event_count`;
- `terminal_event_hash` at exactly that count (`GENESIS_HASH` for zero);
- canonical `issued_at` and `expires_at`;
- `authority`, `key_id`, and `algorithm: "Ed25519"`;
- the checkpoint schema version.

The Agent only receives the checkpoint and an
`authority -> key_id -> public key` allowlist. It has no checkpoint private-key
configuration and no signing operation. The independent authority signs
`canonical_checkpoint_bytes(checkpoint_signing_payload(...))` after observing
the durable journal prefix.

On every production store construction, read, replay, and locked transaction,
verification requires all of the following:

1. The checkpoint is a bounded, regular, single-link, non-aliased file and
   contains strict UTF-8 JSON with no duplicate keys, non-finite values,
   missing fields, or unknown fields.
2. The configured `(authority, key_id)` exists and its Ed25519 signature is
   valid.
3. `issued_at <= trusted_now < expires_at`.
4. Kind and canonical path identity match this exact journal.
5. The current journal contains exactly `event_count` records and the terminal
   record has exactly `terminal_event_hash`. A valid prefix with any uncovered
   tail is not production-readable.

A complete tail truncation before the signed count, an uncovered tail after the
signed count, a validly rehashed fork, checkpoint reuse against another store,
unknown key, forged signature, stale checkpoint, symlink, hard link, or
journal/checkpoint alias fails closed.
Journal records themselves are also size bounded and duplicate-key/non-finite
JSON is rejected.

Every assurance object exposes `covered_count`, `current_count`, and
`tail_count`. `production_ready` is true only when signature/currentness checks
pass and `covered_count == current_count` (`tail_count == 0`). Durable writes
temporarily produce `production_ready=false` until the independent authority
publishes a checkpoint for the new terminal event.

Use production mode explicitly:

```bash
python3 scripts/human_control_cli.py hitl-resume \
  --store <hitl-store> \
  --trust-config <public-trust.json> \
  --journal-mode production \
  --checkpoint <independently-fetched-hitl-checkpoint.json> \
  ...currentness bindings...
```

The default is deliberately `--journal-mode local-test`. Every successful CLI
result includes:

```json
{
  "journal_assurance": {
    "mode": "local-test",
    "checkpoint_required": false,
    "production_ready": false,
    "covered_count": null,
    "current_count": 0,
    "tail_count": null
  }
}
```

Local/test mode retains hash-chain, locking, replay, and receipt verification,
but makes no anti-rollback claim. A production deployment must fetch the newest
checkpoint from an independently protected service or transparency log, issue
a fresh checkpoint after durable appends, and keep the checkpoint private key
outside the Agent runtime. An append that the external authority has not yet
observed remains an untrusted prepare and is rejected by runtime reads. Approval
authorities should independently enforce receipt and decision nonces as well.
