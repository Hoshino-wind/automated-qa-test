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

## Adapter Checklist

- Runtime mode and data boundary are confirmed.
- Every required service has an owner, readiness signal, and safe startup policy.
- Strong signals are separated by layer: UI, request, response/stream, persistence/log, external side effect.
- Seed/fallback/optimistic UI is labeled as weak evidence.
- Mutations use isolated records, unique markers, and cleanup.
- Commands use project-approved helpers, array form, and plan-audit hash binding.
- The adapter contains only relative paths and non-secret metadata.

## Bundled Example

`references/adapters/opc-project.json` is a bundled optional example for an OPC-shaped multi-service checkout. It contains detection markers, service topology, preflight rules, data/evidence boundaries, and a chat stream/session probe template. The generic Python scripts do not contain its project names, ports, or checkout location.

To add another adapter, add a versioned JSON definition following the same fields, extend adapter-registry regression coverage, and keep project-specific prose out of the generic scripts.
