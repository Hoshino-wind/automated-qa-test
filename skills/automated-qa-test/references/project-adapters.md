# Project Adapter Contract

Read this file when a tested feature spans multiple services, databases, streams, background jobs, or project-specific environment rules.

Adapters route evidence; they do not hardcode business acceptance rules. The generic scripts discover optional definitions from `references/adapters/*.json`. A definition owns:

- repository-relative detection markers;
- service ids, roles, relative paths, default URLs, and start commands;
- environment/config candidate paths;
- rules that infer required services from the base URL and plan text;
- project-specific data boundaries and evidence layers;
- optional safe probe-template defaults.

Definitions must never contain an absolute personal checkout path, secrets, credentials, or production mutation instructions. A project is detected only from repository-relative markers. If no definition matches, `adapter=generic` and the plan must supply its own explicit probes.

## Strict onboarding gate

Validate each definition before adding it to `references/adapters/`:

```bash
python3 scripts/adapter_registry.py \
  --definition references/adapters/<adapter>.json \
  --project-root <repo> \
  --out <artifact-dir>/adapter-onboarding.json
```

Omit `--project-root` when validating schema and references before the target
checkout exists. With a project root, the report also records each marker match
and the overall `project_matches` result. If any marker does not match, the
report has `ready=false`, includes an `adapter_markers_not_matched` blocker with
the unmatched markers, and the CLI exits non-zero. A successful report is
deterministic, hash-bound, and explicitly marked `not_evidence=true` and
`not_authorization=true`; it proves only Adapter conformance, not product
behavior or permission to start a service.

The loader is fail-closed:

- schema version and every object field set are exact; unknown fields are
  rejected;
- JSON duplicate keys and non-finite numbers are rejected;
- definitions must be bounded, regular, single-link files opened without
  following symlinks;
- ids are bounded canonical identifiers and registry ids must be unique;
- markers, service paths, and env/config candidates are repository-relative,
  non-escaping paths;
- service URLs are bounded HTTP(S) URLs, service references must resolve, and
  detection must match at most one Adapter;
- `start_command` must parse as argv without shell metacharacters;
- secret-shaped field names and output/input aliases are rejected.

Do not copy a definition into the registry if onboarding fails. Fix the
definition or keep the run on the conservative `generic` route.

## Runtime Flow

Generate current context with an explicit boundary:

```bash
python3 scripts/discover_project_context.py \
  --project-root <repo> \
  --run-dir <artifact-dir> \
  --base-url <url> \
  --runtime-mode test \
  --data-boundary-status "isolated test data; no production data"
```

Then preflight and, when the matched adapter exposes a probe template, synthesize reviewed probes:

```bash
python3 scripts/preflight_runtime.py --run-dir <artifact-dir> --refresh-context --fail-on-blockers
python3 scripts/synthesize_adapter_probes.py --run-dir <artifact-dir> --allow-live-stream --apply
```

Live stream synthesis remains behind `--allow-live-stream`. Persistence checks require an explicit project-approved read-only `--persistence-command`. A stopped service, missing credential, absent helper, or unknown data boundary is a blocker—not evidence of product failure and never a pass.

`discover_project_context.py` and `compile_agent_context.py` bind the selected
definition and repository snapshot into current context. Replacing a marker,
Adapter definition, plan, or repository input after compilation invalidates the
current proof chain; refresh context before execution.

## Adapter Checklist

- Runtime mode and data boundary are confirmed.
- Every required service has an owner, readiness signal, and safe startup policy.
- Strong signals are separated by layer: UI, request, response/stream, persistence/log, external side effect.
- Seed/fallback/optimistic UI is labeled as weak evidence.
- Mutations use isolated records, unique markers, and cleanup.
- Commands use project-approved helpers, array form, and plan-audit hash binding.
- The adapter contains only relative paths and non-secret metadata.
- `adapter_registry.py` reports `ready=true` for the exact definition and, when
  supplied, `project_matches=true` for the intended checkout.
- No second Adapter matches the same complete marker set.

## Bundled Example

`references/adapters/opc-project.json` is a bundled optional example for an OPC-shaped multi-service checkout. It contains detection markers, service topology, preflight rules, data/evidence boundaries, and a chat stream/session probe template. The generic Python scripts do not contain its project names, ports, or checkout location.

To add another adapter:

1. add a versioned JSON definition following the same fields;
2. run `adapter_registry.py` with and without the intended project root;
3. add positive, malformed-input, ambiguous-detection, and path-boundary
   regression coverage;
4. keep project-specific prose, service names, ports, and commands out of the
   generic scripts;
5. run the nightly matrix/fault-injection maintenance gate after merging the
   Adapter tests.

Adapter onboarding is intentionally separate from P2 release admission and
runtime action authorization. A valid Adapter can inform context and probe
routing, but cannot weaken ToolSpec, environment, action-journal, evidence, or
verdict gates.
