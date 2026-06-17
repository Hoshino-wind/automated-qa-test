# Project Adapter Notes

Read this file when the tested feature spans multiple services, databases, message streams, background jobs, or repo-specific environment rules.

Adapters are not business-rule hardcoding. They are evidence routing: which service owns which behavior, which signals prove completion, and which shortcuts are unsafe.

When a checkout is available, run `scripts/discover_project_context.py --project-root <repo> --run-dir <artifact-dir> --base-url <url>` before broad execution. It writes `adapter-context.json` with service discovery, environment boundary prompts, and evidence-layer warnings. Treat that JSON as current-run context; this reference file explains how to interpret it.

For a run that may claim pass, declare the boundary explicitly:

```bash
python3 scripts/discover_project_context.py \
  --project-root <repo> \
  --run-dir <artifact-dir> \
  --base-url <url> \
  --runtime-mode test \
  --data-boundary-status "test database; no production data"
```

Then pass `--require-environment-boundary` to `run_qa_cycle.py`, `qa_agent_loop.py`, or `generate_verdict.py`. A missing `adapter-context.json`, `runtime_mode: unconfirmed`, or an unconfirmed `data_boundary_status` blocks `can_claim_pass=true`.

Before executing probes, run `scripts/preflight_runtime.py --run-dir <artifact-dir> --refresh-context --fail-on-blockers`. It writes `service-preflight.json` with required service readiness, command availability, npm script checks, and env/config path checks without reading secret values. If it reports blockers, treat the run as blocked/setup-needed unless the user explicitly asked for a blocked-state report.

When the user authorizes local/test service startup, run `scripts/service_runtime.py --run-dir <artifact-dir> --start` or `scripts/run_qa_cycle.py --run-dir <artifact-dir> --preflight-runtime --start-missing-services`. This starts only commands from `service-preflight.json` `start_plan`, writes `service-runtime.json` with PID/log/readiness evidence, and then requires a refreshed preflight before product probes.

After planning, run `scripts/synthesize_adapter_probes.py --run-dir <artifact-dir>` to produce `adapter-probes.json`. Use `--apply` only when the generated probes have the required safe inputs. For OPC stream checks, this script deliberately requires `--allow-live-stream` before it adds live WebSocket probes, and requires an explicit `--persistence-command` before it adds persistence checks.

## Adapter Checklist

For each project, identify:

- Runtime mode: local, test, staging, or production. State the data boundary before pass/fail conclusions.
- Services and ports: frontend, API gateway, business API, agent engine, workers, queues, cache.
- Ownership: which config/data belongs in files, DB, search index, object storage, or cache.
- Strong pass signals: UI, API, stream events, DB state, logs, persisted files, external side effects.
- Weak or misleading signals: mock seed, fallback text, cached UI, generated placeholder data, optimistic UI state.
- Safe mutation strategy: test-only records, reversible actions, unique markers, cleanup steps.
- Probe commands: existing repo helper commands first; avoid raw DB writes and destructive shell actions.
- Machine-readable context: `adapter-context.json` exists in the artifact folder or the same assumptions are explicitly documented in `test-charter.md`.
- Environment boundary gate: for real pass claims, `runtime_mode` and `data_boundary_status` are confirmed in `adapter-context.json`, and `qa-verdict.json` was generated with `--require-environment-boundary`.
- Runtime preflight: `service-preflight.json` exists before execution when local services or ports affect the result.
- Service runtime: if the agent started services, `service-runtime.json` records the exact commands, PIDs, logs, and readiness checks.

## OPC Project Adapter

Use this adapter for `/Users/gaozengyu/opc_project`.

### Service Map

- `one_corpus_web`: user-facing Vite app, commonly `http://127.0.0.1:9527`.
- `opc-bot`: Go Gin business API, commonly `http://127.0.0.1:8081`.
- `agent_platform`: FastAPI agent engine, commonly `http://127.0.0.1:8000`.
- `ops_web`: operations console, commonly `http://127.0.0.1:3070`.
- `one_corpus_web` `/api/v1/*` requests normally proxy to `opc-bot`.

### Data And Config Boundaries

- Runtime secrets and endpoints stay in `.env`, `agent_platform/.env`, or `opc-bot/configs/config.yaml`.
- User-editable platform data belongs in PostgreSQL.
- Knowledge metadata/chunks belong in Elasticsearch.
- Uploaded/generated files belong in MinIO.
- Redis is cache only.
- Do not replace DB-backed configuration with local JSON/YAML fixtures unless the user explicitly asks.
- In repo code, follow the repo rule to use ORM/data-access layers rather than ad hoc raw SQL concatenation.

### AI Box / Chat Backtest Evidence

For `one_corpus_web` AI Box or chat-stream verification, separate these evidence layers:

- Catalog/UI seed evidence: which agent cards or local seed data are visible.
- Frontend fallback evidence: whether the UI rendered fallback text or optimistic messages.
- Real stream evidence: WebSocket/SSE/HTTP stream events, especially terminal events such as `answer_done`.
- Backend persistence evidence: session/turn/message state reaching the expected terminal state, such as `completed`.

Strong pass condition for a chat backtest usually requires:

- The user action reaches the intended agent/session.
- The stream emits a successful terminal event such as `answer_done`.
- The returned answer contains the unique run marker in the model/agent reply, not only in user input.
- Persistence evidence shows the turn/session completed when persistence is in scope.

If any layer is missing, report `Inconclusive` or `Blocked` for that layer rather than merging it into a generic pass.

### Common Probe Pattern

Use a unique marker per run, for example `QA_AIBOX_STREAM_OK_<timestamp>`.

Plan the matrix with separate requirements/tests:

- `R-ui`: the intended entry point and agent card are reachable.
- `R-stream`: the live stream emits expected chunks and terminal completion.
- `R-reply`: the returned answer contains the unique marker in the reply.
- `R-persist`: the persisted turn/session state reaches `completed`.
- `R-errors`: no unexplained console, failed network, or backend runtime error affects the flow.

Use `websocket` steps for stream evidence when the browser flow exposes the socket. Use `api` steps for direct HTTP controls. Use `command` steps only for read-only service/log/persistence checks through existing project helpers or safe one-off scripts.

`synthesize_adapter_probes.py` can generate the common OPC chain when authorized:

- WebSocket `/api/v1/agents/ask/ws` with a unique marker, requiring both `answer_done` and the marker in received stream messages.
- Session detail `GET /api/v1/sessions/{session_id}` using the `session_id` extracted from the stream.
- Optional read-only persistence command using `{session_id}` or `{turn_id}` runtime placeholders.

If any required service is down or a safe helper is missing, leave the corresponding row blocked and use `adapter-probes.json` as the next-probe handoff.
