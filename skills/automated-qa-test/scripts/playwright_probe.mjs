#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { constants as fsConstants } from "node:fs";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const NO_HUMAN_AUTHORIZATION_SHA256 = createHash("sha256")
  .update("qa-human-authorization:not-configured:v1", "utf-8")
  .digest("hex");
const MAX_TRUSTED_INPUT_BYTES = 4 * 1024 * 1024;

async function readStableJsonInput(inputPath, label) {
  const resolved = path.resolve(inputPath);
  const flags = fsConstants.O_RDONLY |
    fsConstants.O_CLOEXEC |
    (fsConstants.O_NOFOLLOW || 0);
  const handle = await fs.open(resolved, flags);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 ||
        before.size > MAX_TRUSTED_INPUT_BYTES) {
      throw new Error(
        `${label} must be a bounded single-link regular file.`,
      );
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const current = await fs.lstat(resolved);
    if (before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        current.dev !== before.dev || current.ino !== before.ino ||
        current.size !== before.size ||
        current.mtimeMs !== before.mtimeMs) {
      throw new Error(`${label} changed while being read.`);
    }
    let value;
    try {
      value = JSON.parse(bytes.toString("utf-8"));
    } catch (error) {
      throw new Error(
        `${label} is not valid JSON: ${error.message || String(error)}`,
      );
    }
    if (!isObject(value)) {
      throw new Error(`${label} root must be an object.`);
    }
    return {
      path: resolved,
      bytes,
      value,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  } finally {
    await handle.close();
  }
}

function usage() {
  console.log("Usage: playwright_probe.mjs --plan <test-plan.json> [--plan-audit-summary <plan-audit-summary.json>] [--agent-context <agent-context.json> --action-contracts <action-contracts.json> --action-journal <action-journal.jsonl>]");
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  return idx >= 0 ? process.argv[idx + 1] : undefined;
}

function safeName(value) {
  return String(value || "evidence").replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "") || "evidence";
}

function trimSlashes(value) {
  return String(value || "").replace(/^\/+|\/+$/g, "");
}

function resolveTemplateString(value, ctx, encodeVars = true) {
  if (typeof value !== "string") return value;
  return value.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name) => {
    if (!Object.prototype.hasOwnProperty.call(ctx.vars || {}, name)) {
      throw new Error(`Missing runtime variable for template: ${name}`);
    }
    const raw = String(ctx.vars[name]);
    return encodeVars ? encodeURIComponent(raw) : raw;
  });
}

function compactTimestamp(value) {
  return value.toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
}

function defaultRunId(startedAt) {
  const suffix = Math.random().toString(36).slice(2, 8);
  return `qa_${compactTimestamp(startedAt)}_${suffix}`;
}

function buildRuntimeVars(plan, startedAt) {
  const qaRunId = String(plan.qaRunId || plan.runId || defaultRunId(startedAt));
  const qaMarker = String(plan.qaMarker || `QA_MARKER_${qaRunId}`);
  const configuredVars = {
    ...(isObject(plan.runtimeVars) ? plan.runtimeVars : {}),
    ...(isObject(plan.vars) ? plan.vars : {}),
  };
  return {
    qa_run_id: qaRunId,
    qa_marker: qaMarker,
    qa_started_at: startedAt.toISOString(),
    ...configuredVars,
  };
}

function resolveUrl(baseUrl, step, ctx = {}) {
  if (step.urlTemplate) return resolveTemplateString(String(step.urlTemplate), ctx, step.encodePathVars !== false);
  if (step.url) return step.url;
  const base = String(baseUrl || "").endsWith("/") ? String(baseUrl).slice(0, -1) : String(baseUrl || "");
  const rawPath = step.pathTemplate
    ? resolveTemplateString(String(step.pathTemplate), ctx, step.encodePathVars !== false)
    : step.path || "/";
  const rel = String(rawPath).startsWith("/") ? rawPath : `/${rawPath}`;
  return `${base}${rel}`;
}

function resolveWsUrl(baseUrl, step, ctx = {}) {
  if (step.urlTemplate) return resolveTemplateString(String(step.urlTemplate), ctx, step.encodePathVars !== false);
  if (step.url) return step.url;
  const httpUrl = resolveUrl(baseUrl, step, ctx);
  if (httpUrl.startsWith("https://")) return `wss://${httpUrl.slice("https://".length)}`;
  if (httpUrl.startsWith("http://")) return `ws://${httpUrl.slice("http://".length)}`;
  return httpUrl;
}

function readPath(obj, dottedPath) {
  return String(dottedPath || "").split(".").filter(Boolean).reduce((acc, key) => {
    if (acc === undefined || acc === null) return undefined;
    const arrayMatch = key.match(/^(.+)\[(\d+)\]$/);
    if (arrayMatch) {
      const parent = acc[arrayMatch[1]];
      return Array.isArray(parent) ? parent[Number(arrayMatch[2])] : undefined;
    }
    if (/^\d+$/.test(key) && Array.isArray(acc)) return acc[Number(key)];
    return acc[key];
  }, obj);
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

const sensitiveResolvedValues = new Set();
const sensitiveEnvironmentNames = new Set();

function registerSensitiveResolvedValue(value) {
  if (value === undefined || value === null) return;
  if (Array.isArray(value)) {
    for (const item of value) registerSensitiveResolvedValue(item);
    return;
  }
  if (isObject(value)) {
    for (const item of Object.values(value)) registerSensitiveResolvedValue(item);
    return;
  }
  const text = String(value);
  if (text) sensitiveResolvedValues.add(text);
}

function redactResolvedSecrets(value) {
  let text = String(value);
  const ordered = [...sensitiveResolvedValues].sort((left, right) => right.length - left.length);
  for (const secret of ordered) {
    if (!secret) continue;
    if (text === secret) return "[REDACTED]";
    if (secret.length >= 4) {
      text = text.split(secret).join("[REDACTED]");
      continue;
    }
    const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const bounded = new RegExp(
      `(^|[\\s"'=:,;\\[\\]{}()])${escaped}(?=$|[\\s"',:;\\[\\]{}()])`,
      "g",
    );
    text = text.replace(
      bounded,
      (_match, prefix) => `${prefix}[REDACTED]`,
    );
  }
  return text;
}

function redactString(value) {
  return redactResolvedSecrets(value)
    .replace(/\b(Authorization|Cookie|Set-Cookie)\s*:\s*[^\r\n]+/gi, "$1: [REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[REDACTED_JWT]")
    .replace(/([?&](?:access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|token|session[_-]?token|session|cookie|api[_-]?key|key|secret|password|pwd)=)[^&\s]+/gi, "$1[REDACTED]")
    .replace(/(["']?(?:authorization|password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?token|secret|jwt)["']?\s*[:=]\s*["']?)[^\s"',}\r\n]+/gi, "$1[REDACTED]");
}

function redact(value, depth = 0) {
  if (depth > 8) return "[TRUNCATED_DEPTH]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (/password|secret|token|cookie|authorization|api[_-]?key/i.test(key)) {
        out[key] = "[REDACTED]";
      } else {
        out[key] = redact(item, depth + 1);
      }
    }
    return out;
  }
  return value;
}

function boundedText(value, maxChars = 1200) {
  const text = redactString(String(value ?? ""));
  return text.length > maxChars ? `${text.slice(0, maxChars)}...[truncated]` : text;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function planNeedsCommand(plan) {
  return (plan.scenarios || []).some((scenario) =>
    (scenario.steps || []).some((step) => step && step.action === "command"),
  );
}

async function sha256File(file) {
  const content = await fs.readFile(file);
  return createHash("sha256").update(content).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON rejects non-finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON value: ${typeof value}`);
}

function canonicalSha256(value) {
  return createHash("sha256").update(canonicalJson(value), "utf-8").digest("hex");
}

const RESOLUTION_POLICY = Object.freeze({
  schema_version: 4,
  kind: "qa_runtime_reference_resolution_policy",
  reference_kinds: ["env", "template", "var"],
  strict_closed_reference_objects: true,
  mutually_exclusive_reference_kinds: true,
  immutable_identity_fields: ["scenario.id", "step.action", "step.id"],
  forbidden_dynamic_command_fields: [
    "step.cmd",
    "step.command",
    "step.cwd",
    "step.env",
    "step.shell",
  ],
  forbidden_dynamic_high_risk_network_target_fields: [
    "plan.baseUrl",
    "step.method",
    "step.path",
    "step.pathTemplate",
    "step.url",
    "step.urlTemplate",
  ],
  high_risk_network_redirects_followed: false,
  high_risk_target_identity_binding: "static_scheme_host_port_path_method",
  high_risk_dynamic_values: "credential_headers_only",
  high_risk_absolute_http_target_required: true,
  high_risk_routing_overrides_forbidden: true,
  resolved_command_boundary_revalidation: true,
  command_default_cwd: "plan_directory",
  command_environment_binding: "allowlisted_exact_sha256",
  command_executable_binding:
    "real_absolute_single_link_regular_identity_sha256",
  command_direct_file_binding:
    "existing_argv_regular_files_identity_sha256",
  command_spawn_uses_bound_real_paths: true,
  resolved_values_persisted: false,
  persistent_commitment_mode: "structured_secret_redacted",
  dynamic_reference_values_persisted: false,
  low_entropy_secret_hashes_persisted: false,
  raw_reference_identity_preserved: true,
});
const RESOLUTION_POLICY_SHA256 = canonicalSha256(RESOLUTION_POLICY);
const ACTION_AUTHORITY_KEY_ENV = "QA_ACTION_AUTHORITY_KEY";
const ACTION_AUTHORIZATION_TICKET_ENV = "QA_ACTION_AUTHORIZATION_TICKET";
const TRUSTED_TOOL_REGISTRY_SHA256 = "2a3cd3aab0aaeab972309b344d9e08de0ac996f00aebb6f626327ab87b85c66a";
const TRUSTED_TOOL_SPEC_ROWS = [
  ["addCookies", "40c3931b1420f7d13ad3b304b166ec4bc58e34e68009d4f5e47dd7309cb625a0", "medium", false, 60, 262144, ["browser_state_write", "isolated_test_environment"]],
  ["api", "3f04e9c975a24aebdf47bf99d72f4e7f19318dddaf3fe45c9995cae1a5a8f144", "high", false, 120, 262144, ["isolated_test_environment", "network_request"]],
  ["cleanupApi", "a2dc5843b4e16a346347d76738f627a94e1c2ca8c55271cd2e3c9bcb7a33958a", "high", true, 120, 262144, ["cleanup_execution", "isolated_test_environment", "network_request"]],
  ["click", "3143be081ba3279a0ee585f65b057b0855bd4306123a828805ec1b5773c009a1", "medium", false, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["clickAndWaitForResponse", "5deb4971abdc4c24254f8270a980bccb32430a1aab20f03bf61a7c867023caa7", "medium", false, 120, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["clickRole", "09b9fdf824e243343579b6919f46e225531642e71da84ff94bd708bf3c9497db", "medium", false, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["clickText", "b4f5a0cba4c7280c5fd5d7868d9a96eb227796b0172e45fe9815b6f239cbdbe1", "medium", false, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["command", "19ba70f9c4a1c090510b5988b7823d98d8753b7e8f47198a1218f25017a8515a", "high", false, 300, 1048576, ["command_execution", "isolated_test_environment"]],
  ["dismissIfPresent", "94132d069d550e793074eba58e52e063157ee4f9564e214874d4de8a4eadc33a", "medium", true, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["expectAnyText", "46588b8d9f9dc61cc159cf8444b3eacc4f1b3c7a11b31d0691623b72be2c214a", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectClickable", "9312bb835de405d971a161ba296854a0a1657ff86fc1505683cab743c9832bd3", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectHidden", "4aa9d7145d63ac76086585940f9033298915413709df24b63380b18be579fd63", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectLocatorCount", "2fb1b72349ae4b6ad3d4a1b110c372e7e8bbe8caddbc959f4f4931f98ac71599", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectNoConsoleErrors", "e046deeaf6e33141f0376d8c2164dea45c4f17618d142d22c9db35f04742df88", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectNoFailedResponses", "9dde62f3ac711f54c3ab4c24a1a67f1f167fa2bccf02968509a6551c339b0eec", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectNoRequest", "bd50a05ddba7586ba565aa0a516603c9788cce802c2ee29f4e60162f15b31f59", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectNoRequestFailures", "2546244f90cebf416f01a37673f9b79848a9cb7d9fc8d135d17c280a6185d6a4", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectText", "0217f84fdc6def12f7997ef4bb965ca3bafcd3389f69c41c41642639134f01f8", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectUrlContains", "0ec7a2cdce4b6737b4d62056052cd4c4db4dd889fdc56c2b31af901cd5bcc6e7", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["expectVisible", "92c37786478001f3bd516e09699d319616f38488d9c020de437c33012492fc0a", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["fill", "caf7cf68f65cfbdbfe05c4b86cc3e4ac0aac82f3d7a96c17d2a608665a4dac81", "medium", true, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["fillLabel", "a2c25541bc29006bd4938f34e61e05fc62db3dd05ef6987996ef72299079f454", "medium", true, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["fillPlaceholder", "d8831fa2ca1795b2957201a635dcffdd281d71f229aad9c39b47e9988420d35c", "medium", true, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["goto", "067f930c6800f0916288aca072684f2466612fb86203cead3260da12106f5a7b", "low", true, 120, 262144, ["isolated_test_environment"]],
  ["pollApi", "058f60c5afeca435b348111de6976dd3a285515effd10b488f2a308242b33546", "high", false, 180, 262144, ["isolated_test_environment", "network_request"]],
  ["press", "f32be907c28c84949c6bc3149eeaa1b184febd39dfc1203dd76141642b321940", "medium", false, 60, 262144, ["browser_interaction", "isolated_test_environment"]],
  ["screenshot", "ebfb70078479265c01aceccac3b108a281e44da171fddd37d2433c9d09d60e7b", "low", true, 60, 5242880, ["isolated_test_environment"]],
  ["setLocalStorage", "291b2d64d87a5edd5a1ef98142c74c79a01a8ef0073b596fef4d0b08741aec5c", "medium", false, 60, 262144, ["browser_state_write", "isolated_test_environment"]],
  ["sse", "76ae32cb2e4acb2f7f3d912f5f488c7675d7b0bd3c49dde159371e9fbaeb2396", "medium", true, 180, 262144, ["isolated_test_environment", "network_request"]],
  ["wait", "7005a8232a5bcc4026dcffef389ffd763acf028656814c0821a4e50fc4fa311c", "low", true, 60, 262144, ["isolated_test_environment"]],
  ["waitForLoadState", "4a0abc88fe9e3756430de791e19f43c71bad78f10d0839ec83133142253010a7", "low", true, 120, 262144, ["isolated_test_environment"]],
  ["waitForResponse", "efeddddc66a7ce5aec77c4cf548d5a60cdc60f4cd50c2e8856d56df0d8ccf89f", "low", true, 120, 262144, ["isolated_test_environment"]],
  ["websocket", "69e33ad2374e934333bbb0c78c27363d6f3bb9e9e0f1128c3f8a2c1ce40a957f", "medium", false, 180, 262144, ["isolated_test_environment", "network_request"]],
];
const TRUSTED_TOOL_SPECS = new Map(
  TRUSTED_TOOL_SPEC_ROWS.map(
    ([action, specSha256, riskClass, idempotent, maxTimeoutSeconds, outputLimitBytes, requiredAuthorizations]) => [
      action,
      {
        version: "runner-action@1",
        specSha256,
        riskClass,
        idempotent,
        maxTimeoutSeconds,
        outputLimitBytes,
        requiredAuthorizations,
      },
    ],
  ),
);

function invocationCommitmentSha256(resolvedInvocationSha256) {
  return canonicalSha256({
    schema_version: 1,
    kind: "qa_secret_redacted_invocation_commitment",
    resolved_invocation_sha256: resolvedInvocationSha256,
  });
}

function actionAuthorizationTicketPayload(contracts) {
  return {
    schema_version: 1,
    kind: "qa_action_authorization_ticket",
    run_id: contracts.run_id,
    generation: contracts.generation,
    iteration: contracts.iteration,
    plan_sha256: contracts.plan_sha256,
    context_sha256: contracts.context_sha256,
    plan_audit_sha256: contracts.plan_audit_sha256,
    tool_registry_sha256: contracts.tool_registry_sha256,
    human_authorization_sha256: contracts.human_authorization_sha256,
    contracts_sha256: contracts.contracts_sha256,
    resolution_policy_sha256: RESOLUTION_POLICY_SHA256,
    action_authorization_sha256: contracts.actions.map(
      (item) => item.authorization_sha256,
    ),
  };
}

function consumeActionAuthorizationTicket(contracts) {
  const keyHex = process.env[ACTION_AUTHORITY_KEY_ENV] || "";
  const ticket = process.env[ACTION_AUTHORIZATION_TICKET_ENV] || "";
  delete process.env[ACTION_AUTHORITY_KEY_ENV];
  delete process.env[ACTION_AUTHORIZATION_TICKET_ENV];
  if (!/^[0-9a-f]{64,}$/.test(keyHex) ||
      !/^[0-9a-f]{64}$/.test(ticket)) {
    throw new Error(
      "Action dispatch requires an ephemeral trusted authorization ticket.",
    );
  }
  const expected = createHmac(
    "sha256",
    Buffer.from(keyHex, "hex"),
  ).update(
    canonicalJson(actionAuthorizationTicketPayload(contracts)),
    "utf-8",
  ).digest("hex");
  const expectedBytes = Buffer.from(expected, "hex");
  const ticketBytes = Buffer.from(ticket, "hex");
  if (expectedBytes.length !== ticketBytes.length ||
      !timingSafeEqual(expectedBytes, ticketBytes)) {
    throw new Error(
      "Action authorization ticket does not bind the current contract/context/audit.",
    );
  }
  return canonicalSha256({
    schema_version: 1,
    kind: "qa_action_authorization_ticket_binding",
    ticket,
  });
}

function executionAuthorizationSha256(contract, event) {
  return canonicalSha256({
    schema_version: 1,
    kind: "qa_execution_authorization",
    run_id: event.run_id,
    generation: event.generation,
    iteration: event.iteration,
    scenario_id: event.scenario_id,
    step_id: event.step_id,
    action: event.action,
    raw_step_sha256: event.raw_step_sha256,
    resolution_policy_sha256: event.resolution_policy_sha256,
    resolved_invocation_sha256: event.resolved_invocation_sha256,
    invocation_sha256: event.invocation_sha256,
    execution_controls_sha256: event.execution_controls_sha256,
    authorization_ticket_sha256: event.authorization_ticket_sha256,
    human_authorization_sha256: event.human_authorization_sha256,
    tool_spec_sha256: event.tool_spec_sha256,
    contract_authorization_sha256: contract.authorization_sha256,
  });
}

class DurableActionJournal {
  constructor(
    journalPath,
    contracts,
    events,
    handle,
    authorizationTicketSha256,
    openedIdentity,
  ) {
    this.path = journalPath;
    this.contracts = contracts;
    this.events = events;
    this.handle = handle;
    this.authorizationTicketSha256 = authorizationTicketSha256;
    this.openedIdentity = openedIdentity;
    this.previousHash = events.length ? events[events.length - 1].event_sha256 : null;
    this.nextSequence = events.length + 1;
    this.contractByIdentity = new Map(
      contracts.actions.map((item) => [`${item.scenario_id}\u0000${item.step_id}`, item]),
    );
  }

  static async open(
    journalPath,
    contractsPath,
    planInput,
    planAuditInput,
    contextInput,
  ) {
    if (path.resolve(journalPath) === path.resolve(contractsPath) ||
        path.resolve(journalPath) === planInput.path) {
      throw new Error("Action journal output must not alias plan or contracts input.");
    }
    const contractsInput = await readStableJsonInput(
      contractsPath,
      "action contracts",
    );
    const contracts = contractsInput.value;
    const unsigned = { ...contracts };
    delete unsigned.contracts_sha256;
    if (contracts.schema_version !== 1 ||
        contracts.kind !== "qa_action_contracts" ||
        contracts.not_evidence !== true ||
        canonicalSha256(unsigned) !== contracts.contracts_sha256) {
      throw new Error("Action contracts failed canonical integrity validation.");
    }
    if (planInput.sha256 !== contracts.plan_sha256) {
      throw new Error("Action contracts do not bind the current plan.");
    }
    if (!planAuditInput || !contextInput ||
        planAuditInput.sha256 !== contracts.plan_audit_sha256) {
      throw new Error(
        "Action contracts do not bind the current plan audit.",
      );
    }
    const context = contextInput.value;
    const unsignedContext = { ...context };
    delete unsignedContext.context_sha256;
    if (context.context_sha256 !== contracts.context_sha256 ||
        canonicalSha256(unsignedContext) !== context.context_sha256 ||
        context.ready !== true ||
        !Array.isArray(context.blockers) ||
        context.blockers.length !== 0 ||
        context.semantic_summary?.adapter?.environment_boundary_confirmed !== true ||
        ["production", "prod", "live"].includes(
          String(context.semantic_summary?.adapter?.runtime_mode || "").toLowerCase(),
        ) ||
        context.capability_graph?.tool_registry_sha256 !==
          TRUSTED_TOOL_REGISTRY_SHA256) {
      throw new Error(
        "Action contracts do not bind a current policy-authorized context.",
      );
    }
    if (!Array.isArray(contracts.actions) ||
        contracts.actions.some((item) => !isObject(item) || item.authorized !== true)) {
      throw new Error("Action contracts must explicitly authorize every plan step.");
    }
    if (contracts.tool_registry_sha256 !== TRUSTED_TOOL_REGISTRY_SHA256) {
      throw new Error("Action contracts do not bind the current trusted ToolRegistry.");
    }
    for (const item of contracts.actions) {
      const trustedSpec = TRUSTED_TOOL_SPECS.get(item.action);
      if (!trustedSpec ||
          item.tool_version !== trustedSpec.version ||
          item.tool_spec_sha256 !== trustedSpec.specSha256 ||
          item.risk_class !== trustedSpec.riskClass ||
          item.idempotent !== trustedSpec.idempotent ||
          canonicalJson(item.required_authorizations) !==
            canonicalJson(trustedSpec.requiredAuthorizations) ||
          canonicalJson(item.granted_authorizations) !==
            canonicalJson(trustedSpec.requiredAuthorizations)) {
        throw new Error(
          `Action contract does not match the trusted ToolSpec/policy for ${item.scenario_id}/${item.step_id}.`,
        );
      }
      if (item.resolution_policy_sha256 !== RESOLUTION_POLICY_SHA256) {
        throw new Error("Action contract resolution policy is unsupported.");
      }
      const commandExecutionBinding =
        validateCommandExecutionBindingShape(item);
      const expectedAuthorization = canonicalSha256({
        run_id: contracts.run_id,
        generation: contracts.generation,
        iteration: contracts.iteration,
        scenario_id: item.scenario_id,
        step_id: item.step_id,
        action: item.action,
        plan_sha256: contracts.plan_sha256,
        context_sha256: contracts.context_sha256,
        plan_audit_sha256: contracts.plan_audit_sha256,
        human_authorization_sha256:
          contracts.human_authorization_sha256,
        tool_spec_sha256: item.tool_spec_sha256,
        raw_step_sha256: item.raw_step_sha256,
        resolution_policy_sha256: item.resolution_policy_sha256,
        command_execution_binding_sha256:
          commandExecutionBinding?.binding_sha256 ?? null,
        required_authorizations: item.required_authorizations,
        granted_authorizations: item.granted_authorizations,
      });
      if (expectedAuthorization !== item.authorization_sha256) {
        throw new Error(
          `Action contract authorization hash is invalid for ${item.scenario_id}/${item.step_id}.`,
        );
      }
      if (item.action === "command") {
        const scenario = planInput.value.scenarios.find(
          (candidate) =>
            candidate?.id === item.scenario_id,
        );
        const step = scenario?.steps?.find(
          (candidate) =>
            candidate?.id === item.step_id,
        );
        if (!step || step.action !== "command") {
          throw new Error(
            `Bound command is absent from the current plan: ${item.scenario_id}/${item.step_id}.`,
          );
        }
        await verifyCurrentCommandExecutionBinding(
          item,
          step,
        );
      }
    }
    const authorizationTicketSha256 =
      consumeActionAuthorizationTicket(contracts);
    await ensureDir(path.dirname(journalPath));
    let handle;
    try {
      handle = await fs.open(
        journalPath,
        fsConstants.O_RDWR |
          fsConstants.O_CREAT |
          fsConstants.O_APPEND |
          fsConstants.O_CLOEXEC |
          (fsConstants.O_NOFOLLOW || 0),
        0o600,
      );
      const info = await handle.stat();
      if (!info.isFile() || info.nlink !== 1) {
        throw new Error("Action journal must be a single-link regular file.");
      }
    } catch (error) {
      if (handle) await handle.close();
      throw error;
    }
    const raw = await handle.readFile("utf-8");
    const currentJournal = await fs.lstat(journalPath);
    const openedJournal = await handle.stat();
    if (currentJournal.dev !== openedJournal.dev ||
        currentJournal.ino !== openedJournal.ino ||
        currentJournal.nlink !== 1) {
      throw new Error(
        "Action journal path changed after its pinned handle was opened.",
      );
    }
    if (raw && !raw.endsWith("\n")) throw new Error("Action journal contains a partial final line.");
    const events = raw ? raw.trimEnd().split("\n").map((line) => JSON.parse(line)) : [];
    let previous = null;
    const intents = new Map();
    const committed = new Set();
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      const unsignedEvent = { ...event };
      delete unsignedEvent.event_sha256;
      if (event.sequence !== index + 1 ||
          event.previous_event_sha256 !== previous ||
          canonicalSha256(unsignedEvent) !== event.event_sha256) {
        throw new Error(`Action journal hash chain is invalid at sequence ${index + 1}.`);
      }
      const contract = contracts.actions.find((item) =>
        item.scenario_id === event.scenario_id &&
        item.step_id === event.step_id);
      const currentEvent = event.run_id === contracts.run_id &&
        event.generation === contracts.generation &&
        event.iteration === contracts.iteration;
      if (currentEvent) {
        if (!contract ||
            event.action !== contract.action ||
            event.tool_spec_sha256 !== contract.tool_spec_sha256 ||
            event.raw_step_sha256 !== contract.raw_step_sha256 ||
            event.resolution_policy_sha256 !== contract.resolution_policy_sha256 ||
            event.human_authorization_sha256 !==
              contracts.human_authorization_sha256 ||
            event.idempotent !== contract.idempotent) {
          throw new Error(`Action journal event does not match its contract at sequence ${index + 1}.`);
        }
        if (event.invocation_sha256 !== invocationCommitmentSha256(event.resolved_invocation_sha256) ||
            event.execution_authorization_sha256 !==
              executionAuthorizationSha256(contract, event)) {
          throw new Error(`Action journal execution authorization is invalid at sequence ${index + 1}.`);
        }
        const expectedIdempotencyKey = canonicalSha256({
          run_id: event.run_id,
          generation: event.generation,
          iteration: event.iteration,
          scenario_id: event.scenario_id,
          step_id: event.step_id,
          action: event.action,
          invocation_sha256: event.invocation_sha256,
          execution_authorization_sha256: event.execution_authorization_sha256,
        });
        if (event.idempotency_key !== expectedIdempotencyKey) {
          throw new Error(`Action journal idempotency key is invalid at sequence ${index + 1}.`);
        }
      }
      if (event.kind === "intent") intents.set(event.sequence, event);
      if (event.kind === "commit") {
        if (!intents.has(event.intent_sequence) || committed.has(event.intent_sequence)) {
          throw new Error(`Action journal commit is orphaned at sequence ${event.sequence}.`);
        }
        const intent = intents.get(event.intent_sequence);
        for (const field of [
          "run_id", "generation", "iteration", "scenario_id", "step_id",
          "action", "invocation_sha256", "resolved_invocation_sha256",
          "execution_controls_sha256", "execution_authorization_sha256",
          "authorization_ticket_sha256", "raw_step_sha256",
          "human_authorization_sha256",
          "resolution_policy_sha256", "tool_spec_sha256",
          "idempotency_key", "idempotent",
        ]) {
          if (event[field] !== intent[field]) {
            throw new Error(`Action journal commit mismatches intent field ${field}.`);
          }
        }
        committed.add(event.intent_sequence);
      }
      previous = event.event_sha256;
    }
    if (contracts.human_authorization_sha256 !==
        NO_HUMAN_AUTHORIZATION_SHA256 &&
        events.some((event) =>
          event.run_id === contracts.run_id &&
          event.generation === contracts.generation &&
          event.iteration === contracts.iteration)) {
      throw new Error(
        "Human-authorized execution intent already has a durable action event; reconcile without redispatch.",
      );
    }
    const journal = new DurableActionJournal(
      journalPath,
      contracts,
      events,
      handle,
      authorizationTicketSha256,
      {
        dev: openedJournal.dev,
        ino: openedJournal.ino,
      },
    );
    for (const [sequence, intent] of intents.entries()) {
      if (committed.has(sequence)) continue;
      if (intent.idempotent !== true) {
        throw new Error(
          `Uncertain non-idempotent action requires human reconciliation: ${intent.scenario_id}/${intent.step_id} (intent ${sequence}).`,
        );
      }
      await journal.appendCommit(intent, sequence, "abandoned_safe");
    }
    return journal;
  }

  contract(scenario, step) {
    const key = `${scenario.id}\u0000${step.id || ""}`;
    const contract = this.contractByIdentity.get(key);
    if (!contract || contract.action !== step.action || contract.authorized !== true) {
      throw new Error(`No authorized ToolSpec contract for ${scenario.id}/${step.id || ""}.`);
    }
    if (canonicalSha256(step) !== contract.raw_step_sha256) {
      throw new Error(
        `Raw step does not match its authorized contract for ${scenario.id}/${step.id || ""}.`,
      );
    }
    if (contract.resolution_policy_sha256 !== RESOLUTION_POLICY_SHA256) {
      throw new Error(
        `Resolution policy does not match the authorized contract for ${scenario.id}/${step.id || ""}.`,
      );
    }
    return contract;
  }

  async intent(
    scenario,
    rawStep,
    resolvedStep,
    executionControlsHash = null,
  ) {
    const contract = this.contract(scenario, rawStep);
    if (!isObject(resolvedStep) ||
        resolvedStep.id !== rawStep.id ||
        resolvedStep.action !== rawStep.action ||
        scenario.id !== contract.scenario_id) {
      throw new Error(
        `Resolved action identity changed for ${scenario.id}/${rawStep.id || ""}.`,
      );
    }
    const resolvedInvocationSha256 = canonicalSha256(
      secretRedactedInvocationPayload(
        scenario,
        rawStep,
        resolvedStep,
        contract,
      ),
    );
    const invocationSha256 = invocationCommitmentSha256(
      resolvedInvocationSha256,
    );
    const controlsSha256 = executionControlsHash ||
      executionControlsSha256(rawStep, resolvedStep, contract, {
        maxArtifactChars: contract.output_limit_bytes || 10000,
        rawBaseUrl: null,
        baseUrl: null,
        rawDefaultHeaders: {},
        defaultHeaders: {},
        rawExtraHTTPHeaders: {},
        extraHTTPHeaders: {},
      });
    const executionAuthorization = executionAuthorizationSha256(
      contract,
      {
      run_id: this.contracts.run_id,
      generation: this.contracts.generation,
      iteration: this.contracts.iteration,
      scenario_id: scenario.id,
      step_id: rawStep.id || "",
      action: rawStep.action,
      raw_step_sha256: contract.raw_step_sha256,
      resolution_policy_sha256: contract.resolution_policy_sha256,
      resolved_invocation_sha256: resolvedInvocationSha256,
      execution_controls_sha256: controlsSha256,
      authorization_ticket_sha256: this.authorizationTicketSha256,
      human_authorization_sha256:
        this.contracts.human_authorization_sha256,
      invocation_sha256: invocationSha256,
      tool_spec_sha256: contract.tool_spec_sha256,
      },
    );
    const idempotencyKey = canonicalSha256({
      run_id: this.contracts.run_id,
      generation: this.contracts.generation,
      iteration: this.contracts.iteration,
      scenario_id: scenario.id,
      step_id: rawStep.id || "",
      action: rawStep.action,
      invocation_sha256: invocationSha256,
      execution_authorization_sha256: executionAuthorization,
    });
    const event = await this.append({
      kind: "intent",
      intent_sequence: null,
      scenario_id: scenario.id,
      step_id: rawStep.id || "",
      action: rawStep.action,
      invocation_sha256: invocationSha256,
      resolved_invocation_sha256: resolvedInvocationSha256,
      execution_controls_sha256: controlsSha256,
      authorization_ticket_sha256: this.authorizationTicketSha256,
      execution_authorization_sha256: executionAuthorization,
      human_authorization_sha256:
        this.contracts.human_authorization_sha256,
      raw_step_sha256: contract.raw_step_sha256,
      resolution_policy_sha256: contract.resolution_policy_sha256,
      tool_spec_sha256: contract.tool_spec_sha256,
      idempotency_key: idempotencyKey,
      idempotent: contract.idempotent,
      status: "pending",
    });
    return { event, contract };
  }

  async skipped(scenario, rawStep) {
    let controlsSha256 = null;
    if (rawStep.action === "command") {
      const contract = this.contract(scenario, rawStep);
      const commandDispatch =
        await verifyCurrentCommandExecutionBinding(
          contract,
          rawStep,
        );
      controlsSha256 = executionControlsSha256(
        rawStep,
        rawStep,
        contract,
        {
          maxArtifactChars:
            contract.output_limit_bytes || 10000,
          rawBaseUrl: null,
          baseUrl: null,
          rawDefaultHeaders: {},
          defaultHeaders: {},
          rawExtraHTTPHeaders: {},
          extraHTTPHeaders: {},
        },
        commandDispatch,
      );
    }
    const token = await this.intent(
      scenario,
      rawStep,
      rawStep,
      controlsSha256,
    );
    await this.commit(token, "skipped");
  }

  async commit(token, status) {
    await this.appendCommit(token.event, token.event.sequence, status);
  }

  async appendCommit(intent, intentSequence, status) {
    return await this.append({
      kind: "commit",
      intent_sequence: intentSequence,
      run_id: intent.run_id,
      generation: intent.generation,
      iteration: intent.iteration,
      scenario_id: intent.scenario_id,
      step_id: intent.step_id,
      action: intent.action,
      invocation_sha256: intent.invocation_sha256,
      resolved_invocation_sha256: intent.resolved_invocation_sha256,
      execution_controls_sha256: intent.execution_controls_sha256,
      authorization_ticket_sha256: intent.authorization_ticket_sha256,
      execution_authorization_sha256: intent.execution_authorization_sha256,
      human_authorization_sha256:
        intent.human_authorization_sha256,
      raw_step_sha256: intent.raw_step_sha256,
      resolution_policy_sha256: intent.resolution_policy_sha256,
      tool_spec_sha256: intent.tool_spec_sha256,
      idempotency_key: intent.idempotency_key,
      idempotent: intent.idempotent,
      status,
    });
  }

  async append(fields) {
    const currentBefore = await fs.lstat(this.path);
    if (currentBefore.dev !== this.openedIdentity.dev ||
        currentBefore.ino !== this.openedIdentity.ino ||
        currentBefore.nlink !== 1) {
      throw new Error(
        "Action journal path was replaced before durable append.",
      );
    }
    const {
      run_id = this.contracts.run_id,
      generation = this.contracts.generation,
      iteration = this.contracts.iteration,
      ...eventFields
    } = fields;
    const unsigned = {
      schema_version: 1,
      sequence: this.nextSequence,
      previous_event_sha256: this.previousHash,
      ...eventFields,
      run_id,
      generation,
      iteration,
      occurred_at: new Date().toISOString(),
    };
    const event = { ...unsigned, event_sha256: canonicalSha256(unsigned) };
    await this.handle.write(`${canonicalJson(event)}\n`, null, "utf-8");
    await this.handle.sync();
    const currentAfter = await fs.lstat(this.path);
    if (currentAfter.dev !== this.openedIdentity.dev ||
        currentAfter.ino !== this.openedIdentity.ino ||
        currentAfter.nlink !== 1) {
      throw new Error(
        "Action journal path was replaced during durable append.",
      );
    }
    this.events.push(event);
    this.previousHash = event.event_sha256;
    this.nextSequence += 1;
    return event;
  }

  async close() {
    if (!this.handle) return;
    const handle = this.handle;
    this.handle = null;
    await handle.close();
  }
}

async function validateCommandPlanBinding(
  plan,
  planInput,
  auditInput,
) {
  if (!planNeedsCommand(plan)) return;
  if (!auditInput) {
    throw new Error("Command plans require --plan-audit-summary; refusing to execute an unvalidated local command.");
  }
  const audit = auditInput.value;
  const expectedPlan = planInput.path;
  const boundPlan = audit.plan ? path.resolve(String(audit.plan)) : "";
  const expectedHash = planInput.sha256;
  const boundHash = audit.artifact_hashes?.plan_sha256;
  if (audit.passed !== true) throw new Error("Command plan audit is not passed.");
  if (boundPlan !== expectedPlan) throw new Error("Command plan audit path does not match --plan.");
  if (!boundHash || boundHash !== expectedHash) throw new Error("Command plan changed after validation; SHA-256 binding mismatch.");
}

const REFERENCE_KEYS = new Set(["env", "$env", "var", "$var", "template", "$template"]);
const ENV_REFERENCE_FIELDS = new Set(["env", "$env", "prefix", "suffix", "json"]);
const VAR_REFERENCE_FIELDS = new Set(["var", "$var", "prefix", "suffix", "json"]);
const TEMPLATE_REFERENCE_FIELDS = new Set(["template", "$template", "encodeVars", "json"]);
const COMMAND_CONTROL_FIELDS = ["command", "cmd", "cwd", "shell", "env"];
const HIGH_RISK_NETWORK_ACTIONS = new Set(["api", "cleanupApi", "pollApi"]);
const CREDENTIAL_HEADER_NAMES = new Set([
  "api-key",
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-access-token",
  "x-api-key",
  "x-auth-token",
]);
const ROUTING_HEADER_NAMES = new Set([
  ":authority",
  "forwarded",
  "host",
  "x-http-method-override",
  "x-method-override",
  "x-original-url",
  "x-rewrite-url",
]);
const ROUTING_LAUNCH_ARGUMENT_PREFIXES = [
  "--host-resolver-rules",
  "--host-rules",
  "--proxy-bypass-list",
  "--proxy-pac-url",
  "--proxy-server",
];
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SECRETISH_NAME_PATTERN = /authorization|auth|access[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|secret|jwt|cookie|password|^sid$/i;
const SENSITIVE_REFERENCE_PATH_PATTERN = /(?:^|\.)(?:headers?|cookies?|cookie|body|json)(?:\.|$)/i;
const DESTRUCTIVE_COMMAND_PATTERN = /\b(?:rm\s+-rf|drop\s+table|truncate\s+table|delete\s+from|update\s+\w+\s+set|insert\s+into|gh\s+repo\s+delete|kubectl\s+delete|terraform\s+destroy|(?:npm|pnpm|yarn)\s+(?:publish|install|add)|(?:pip|pip3)\s+install)\b/i;
const SECRET_COMMAND_PATH_PATTERN = /(?:^|[\/\s"'=])(?:\.env(?:\.|\/|\b)|[^\/\s]*credentials?[^\/\s]*|[^\/\s]*(?:private[_-]?key|password|secret|token)[^\/\s]*|\/(?:run\/)?secrets?(?:\/|\b))/i;
const SECRET_COMMAND_READ_PATTERN = /\b(?:cat|tac|head|tail|less|more|grep|sed|awk|dd|cp|scp|rsync|curl|wget|printenv|env|set|export|base64|openssl|tar|zip|python|python3|node|ruby|sh|bash|zsh)\b/i;
const INLINE_SECRET_ACCESS_PATTERN = /\b(?:process\.env|os\.environ|getenv|Deno\.env|ENV\[|printenv)\b/i;

function objectHasReferenceDiscriminator(value) {
  if (!isObject(value)) return false;
  if (["$env", "$var", "$template"].some((key) => Object.prototype.hasOwnProperty.call(value, key))) {
    return true;
  }
  for (const key of ["env", "var", "template"]) {
    if (typeof value[key] === "string") return true;
  }
  const keys = Object.keys(value);
  return keys.length > 0 && keys.every((key) =>
    REFERENCE_KEYS.has(key) ||
    ["prefix", "suffix", "json", "encodeVars"].includes(key));
}

function parseReferenceObject(value, location) {
  if (!objectHasReferenceDiscriminator(value)) return null;
  const present = [...REFERENCE_KEYS].filter((key) =>
    Object.prototype.hasOwnProperty.call(value, key));
  if (present.length !== 1) {
    throw new Error(
      `Dynamic reference at ${location} must select exactly one of env/$env, var/$var, or template/$template.`,
    );
  }
  const discriminator = present[0];
  const kind = discriminator.replace("$", "");
  const allowed = kind === "env"
    ? ENV_REFERENCE_FIELDS
    : kind === "var"
      ? VAR_REFERENCE_FIELDS
      : TEMPLATE_REFERENCE_FIELDS;
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length) {
    throw new Error(
      `Dynamic ${kind} reference at ${location} is not a closed reference object; unknown fields: ${unknown.sort().join(", ")}.`,
    );
  }
  const referenceValue = value[discriminator];
  if (typeof referenceValue !== "string" || !referenceValue.trim() || referenceValue.trim() !== referenceValue) {
    throw new Error(`Dynamic ${kind} reference at ${location} requires non-empty trimmed text.`);
  }
  if (kind !== "template" && !ENV_NAME_PATTERN.test(referenceValue)) {
    throw new Error(`Dynamic ${kind} reference at ${location} has an invalid variable name.`);
  }
  if ("prefix" in value && typeof value.prefix !== "string") {
    throw new Error(`Dynamic ${kind} reference at ${location} prefix must be a string.`);
  }
  if ("suffix" in value && typeof value.suffix !== "string") {
    throw new Error(`Dynamic ${kind} reference at ${location} suffix must be a string.`);
  }
  if ("json" in value && typeof value.json !== "boolean") {
    throw new Error(`Dynamic ${kind} reference at ${location} json must be a boolean.`);
  }
  if ("encodeVars" in value && typeof value.encodeVars !== "boolean") {
    throw new Error(`Dynamic template reference at ${location} encodeVars must be a boolean.`);
  }
  return { kind, discriminator, referenceValue };
}

function structuredSecretRedactedValue(rawValue, resolvedValue, location) {
  if (Array.isArray(rawValue)) {
    if (!Array.isArray(resolvedValue) ||
        rawValue.length !== resolvedValue.length) {
      throw new Error(
        `Resolved structure changed outside a reference at ${location}.`,
      );
    }
    return rawValue.map((item, index) =>
      structuredSecretRedactedValue(
        item,
        resolvedValue[index],
        `${location}[${index}]`,
      ));
  }
  if (isObject(rawValue)) {
    const reference = parseReferenceObject(rawValue, location);
    if (reference) {
      return {
        $dynamic_reference: {
          alias: reference.discriminator,
          kind: reference.kind,
          location,
          source: reference.referenceValue,
          raw_reference_sha256: canonicalSha256(rawValue),
          resolved_value: "[REDACTED]",
        },
      };
    }
    if (!isObject(resolvedValue) ||
        canonicalJson(Object.keys(rawValue).sort()) !==
          canonicalJson(Object.keys(resolvedValue).sort())) {
      throw new Error(
        `Resolved object fields changed outside a reference at ${location}.`,
      );
    }
    const out = {};
    for (const [key, item] of Object.entries(rawValue)) {
      out[key] = structuredSecretRedactedValue(
        item,
        resolvedValue[key],
        `${location}.${key}`,
      );
    }
    return out;
  }
  return resolvedValue;
}

function secretRedactedInvocationPayload(
  scenario,
  rawStep,
  resolvedStep,
  contract,
) {
  const location = `scenario.${scenario.id}.step.${rawStep.id || ""}`;
  return {
    schema_version: 2,
    kind: "qa_secret_redacted_resolved_invocation",
    scenario_id: scenario.id,
    step_id: rawStep.id || "",
    action: rawStep.action,
    arguments: structuredSecretRedactedValue(
      rawStep,
      resolvedStep,
      location,
    ),
    tool_version: contract.tool_version,
    tool_spec_sha256: contract.tool_spec_sha256,
  };
}

function assertNoDynamicReferences(value, location) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoDynamicReferences(item, `${location}[${index}]`));
    return;
  }
  if (!isObject(value)) return;
  if (objectHasReferenceDiscriminator(value)) {
    parseReferenceObject(value, location);
    throw new Error(`Dynamic references are forbidden in execution control field ${location}.`);
  }
  for (const [key, item] of Object.entries(value)) {
    assertNoDynamicReferences(item, `${location}.${key}`);
  }
}

function validateHighRiskHeaders(value, location) {
  if (!isObject(value)) {
    throw new Error(`${location} must be a static header object.`);
  }
  for (const [rawName, headerValue] of Object.entries(value)) {
    const name = rawName.trim().toLowerCase();
    if (ROUTING_HEADER_NAMES.has(name) || name.startsWith("x-forwarded-")) {
      throw new Error(
        `High-risk network actions forbid routing header ${rawName}.`,
      );
    }
    if (!CREDENTIAL_HEADER_NAMES.has(name)) {
      assertNoDynamicReferences(headerValue, `${location}.${rawName}`);
    }
  }
}

function absoluteHighRiskNetworkTarget(baseUrl, step, location) {
  const target = typeof step.url === "string" && step.url
    ? step.url
    : (() => {
        if (typeof baseUrl !== "string" || !baseUrl) {
          throw new Error(
            `High-risk network action ${location} requires an absolute step.url or plan.baseUrl.`,
          );
        }
        const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
        const rawPath = step.path ?? "/";
        if (typeof rawPath !== "string") {
          throw new Error(
            `High-risk network action ${location} requires a static step.path.`,
          );
        }
        return `${base}${rawPath.startsWith("/") ? rawPath : `/${rawPath}`}`;
      })();
  let parsed;
  try {
    parsed = new URL(target);
  } catch (error) {
    throw new Error(
      `High-risk network target ${location} must be an absolute HTTP(S) URL: ${error.message || String(error)}`,
    );
  }
  if (!["http:", "https:"].includes(parsed.protocol) ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.hash) {
    throw new Error(
      `High-risk network target ${location} must be an absolute credential-free HTTP(S) URL without a fragment.`,
    );
  }
  return parsed.href;
}

function validateHighRiskNetworkBoundary(plan, step, stepLocation) {
  for (const field of ["method", "url", "path"]) {
    if (Object.prototype.hasOwnProperty.call(step, field) &&
        typeof step[field] !== "string") {
      throw new Error(
        `High-risk network actions require a static ${stepLocation}.${field}.`,
      );
    }
  }
  for (const field of ["urlTemplate", "pathTemplate"]) {
    if (Object.prototype.hasOwnProperty.call(step, field)) {
      throw new Error(
        `High-risk network actions forbid dynamic ${stepLocation}.${field}.`,
      );
    }
  }
  absoluteHighRiskNetworkTarget(plan.baseUrl, step, stepLocation);
  if (typeof plan.baseUrl === "string" && plan.baseUrl) {
    const parsedBase = new URL(plan.baseUrl);
    if (parsedBase.search || parsedBase.hash) {
      throw new Error(
        "High-risk plan.baseUrl cannot contain a query or fragment.",
      );
    }
  }

  if (plan.contextOptions !== undefined) {
    if (!isObject(plan.contextOptions)) {
      throw new Error("plan.contextOptions must be a static object.");
    }
    for (const field of ["baseURL", "proxy"]) {
      if (Object.prototype.hasOwnProperty.call(plan.contextOptions, field)) {
        throw new Error(
          `High-risk network actions forbid plan.contextOptions.${field}.`,
        );
      }
    }
    for (const [field, value] of Object.entries(plan.contextOptions)) {
      if (field === "extraHTTPHeaders") {
        validateHighRiskHeaders(
          value,
          "plan.contextOptions.extraHTTPHeaders",
        );
      } else {
        assertNoDynamicReferences(value, `plan.contextOptions.${field}`);
      }
    }
  }

  if (plan.launchOptions !== undefined) {
    if (!isObject(plan.launchOptions)) {
      throw new Error("plan.launchOptions must be a static object.");
    }
    if (Object.prototype.hasOwnProperty.call(plan.launchOptions, "proxy")) {
      throw new Error(
        "High-risk network actions forbid plan.launchOptions.proxy.",
      );
    }
    assertNoDynamicReferences(plan.launchOptions, "plan.launchOptions");
    const args = plan.launchOptions.args ?? [];
    if (Array.isArray(args) && args.some((argument) =>
      typeof argument === "string" &&
      ROUTING_LAUNCH_ARGUMENT_PREFIXES.some((prefix) =>
        argument.startsWith(prefix)))) {
      throw new Error(
        "High-risk network actions forbid browser routing arguments.",
      );
    }
  }

  for (const field of ["defaultHeaders", "extraHTTPHeaders"]) {
    if (Object.prototype.hasOwnProperty.call(plan, field)) {
      validateHighRiskHeaders(plan[field], `plan.${field}`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(step, "headers")) {
    validateHighRiskHeaders(step.headers, `${stepLocation}.headers`);
  }
  for (const [field, value] of Object.entries(step)) {
    if (field !== "headers") {
      assertNoDynamicReferences(value, `${stepLocation}.${field}`);
    }
  }
}

function validatePlanReferenceBoundary(plan) {
  if (!isObject(plan) || objectHasReferenceDiscriminator(plan)) {
    throw new Error("Plan root must be a static object and cannot be replaced by a dynamic reference.");
  }
  if (!Array.isArray(plan.scenarios)) {
    throw new Error("plan.scenarios must be a static array.");
  }
  const hasHighRiskNetworkAction = plan.scenarios.some((scenario) =>
    isObject(scenario) &&
    Array.isArray(scenario.steps) &&
    scenario.steps.some((step) =>
      isObject(step) && HIGH_RISK_NETWORK_ACTIONS.has(step.action)));
  if (hasHighRiskNetworkAction &&
      Object.prototype.hasOwnProperty.call(plan, "baseUrl") &&
      typeof plan.baseUrl !== "string") {
    throw new Error(
      "High-risk network actions require a static plan.baseUrl.",
    );
  }
  for (let scenarioIndex = 0; scenarioIndex < plan.scenarios.length; scenarioIndex += 1) {
    const scenario = plan.scenarios[scenarioIndex];
    const scenarioLocation = `plan.scenarios[${scenarioIndex}]`;
    if (!isObject(scenario) || objectHasReferenceDiscriminator(scenario)) {
      throw new Error(`${scenarioLocation} must be a static scenario object.`);
    }
    if (typeof scenario.id !== "string" || !scenario.id) {
      throw new Error(`${scenarioLocation}.id must be a static non-empty string.`);
    }
    if (!Array.isArray(scenario.steps)) {
      throw new Error(`${scenarioLocation}.steps must be a static array.`);
    }
    for (let stepIndex = 0; stepIndex < scenario.steps.length; stepIndex += 1) {
      const step = scenario.steps[stepIndex];
      const stepLocation = `${scenarioLocation}.steps[${stepIndex}]`;
      if (!isObject(step) || objectHasReferenceDiscriminator(step)) {
        throw new Error(`${stepLocation} must be a static step object.`);
      }
      if ((Object.prototype.hasOwnProperty.call(step, "id") &&
           (typeof step.id !== "string" || !step.id)) ||
          typeof step.action !== "string" || !step.action) {
        throw new Error(
          `${stepLocation} action and any declared id must be static non-empty strings.`,
        );
      }
      if (step.action === "command") {
        for (const field of COMMAND_CONTROL_FIELDS) {
          if (Object.prototype.hasOwnProperty.call(step, field)) {
            assertNoDynamicReferences(step[field], `${stepLocation}.${field}`);
          }
        }
      }
      if (HIGH_RISK_NETWORK_ACTIONS.has(step.action)) {
        validateHighRiskNetworkBoundary(plan, step, stepLocation);
      }
    }
  }
}

function resolveRuntimeRefs(value, ctx, location = "step") {
  if (Array.isArray(value)) {
    return value.map((item, index) => resolveRuntimeRefs(item, ctx, `${location}[${index}]`));
  }
  if (isObject(value)) {
    const reference = parseReferenceObject(value, location);
    if (reference) {
      if (reference.kind === "env") {
        throw new Error(`Environment reference at ${location} was not resolved during plan loading.`);
      }
      if (reference.kind === "template") {
        const rendered = resolveTemplateString(
          reference.referenceValue,
          ctx,
          value.encodeVars === true,
        );
        const resolved = value.json === true ? JSON.parse(rendered) : rendered;
        if (SENSITIVE_REFERENCE_PATH_PATTERN.test(location)) {
          registerSensitiveResolvedValue(resolved);
        }
        return resolved;
      }
      const varName = reference.referenceValue;
      if (!Object.prototype.hasOwnProperty.call(ctx.vars || {}, varName)) {
        throw new Error(`Missing runtime variable: ${varName}`);
      }
      const raw = ctx.vars[varName];
      const rendered = `${value.prefix || ""}${raw}${value.suffix || ""}`;
      const resolved = value.json === true ? JSON.parse(rendered) : rendered;
      if (SECRETISH_NAME_PATTERN.test(varName) ||
          SENSITIVE_REFERENCE_PATH_PATTERN.test(location)) {
        registerSensitiveResolvedValue(resolved);
      }
      return resolved;
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = resolveRuntimeRefs(item, ctx, `${location}.${key}`);
    }
    return out;
  }
  return value;
}

function resolveEnvRefs(value, location = "plan") {
  if (Array.isArray(value)) {
    return value.map((item, index) => resolveEnvRefs(item, `${location}[${index}]`));
  }
  if (isObject(value)) {
    const reference = parseReferenceObject(value, location);
    if (reference) {
      if (reference.kind !== "env") {
        return { ...value };
      }
      const envName = reference.referenceValue;
      const raw = process.env[envName];
      if (raw === undefined) throw new Error(`Missing required environment variable: ${envName}`);
      const rendered = `${value.prefix || ""}${raw}${value.suffix || ""}`;
      const resolved = value.json === true ? JSON.parse(rendered) : rendered;
      registerSensitiveResolvedValue(raw);
      registerSensitiveResolvedValue(resolved);
      sensitiveEnvironmentNames.add(envName);
      return resolved;
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = resolveEnvRefs(item, `${location}.${key}`);
    }
    return out;
  }
  return value;
}

function validateResolvedCommandBoundary(rawStep, resolvedStep) {
  for (const field of COMMAND_CONTROL_FIELDS) {
    if (canonicalSha256(rawStep[field] ?? null) !== canonicalSha256(resolvedStep[field] ?? null)) {
      throw new Error(`Resolved command control field changed dynamically: step.${field}.`);
    }
  }
  const commandValue = resolvedStep.command || resolvedStep.cmd;
  if (!commandValue) throw new Error("command step requires command or cmd.");
  if (!Array.isArray(commandValue) || !commandValue.length ||
      commandValue.some((part) => typeof part !== "string" || !part)) {
    throw new Error(
      "Resolved command must be a non-empty string argv array under the trusted ToolSpec.",
    );
  }
  if (resolvedStep.shell === true) {
    throw new Error("Resolved command cannot enable a shell outside the trusted ToolSpec.");
  }
  if (resolvedStep.cwd !== undefined &&
      (typeof resolvedStep.cwd !== "string" || !resolvedStep.cwd)) {
    throw new Error("Resolved command cwd must be a non-empty static string.");
  }
  const commandParts = Array.isArray(commandValue)
    ? commandValue.map((part) => String(part))
    : [String(commandValue)];
  const commandText = commandParts.join(" ");
  if (DESTRUCTIVE_COMMAND_PATTERN.test(commandText)) {
    throw new Error("Resolved command failed the destructive command boundary.");
  }
  if (INLINE_SECRET_ACCESS_PATTERN.test(commandText) ||
      (SECRET_COMMAND_PATH_PATTERN.test(commandText) &&
       SECRET_COMMAND_READ_PATTERN.test(commandText))) {
    throw new Error("Resolved command failed the secret read/exfiltration boundary.");
  }
}

const COMMAND_INHERITED_ENV_NAMES = [
  "CI",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NODE_PATH",
  "PATH",
  "PYTHONPATH",
  "TERM",
  "TMPDIR",
];
const MAX_COMMAND_FILE_BYTES = 256 * 1024 * 1024;

function buildCommandEnvironment(step) {
  const explicit = step.env === undefined ? {} : step.env;
  if (!isObject(explicit) ||
      Object.values(explicit).some((value) => typeof value !== "string")) {
    throw new Error("Command env must be a static string-to-string object.");
  }
  const env = {};
  for (const name of COMMAND_INHERITED_ENV_NAMES) {
    if (typeof process.env[name] === "string") env[name] = process.env[name];
  }
  Object.assign(env, explicit);
  for (const name of sensitiveEnvironmentNames) delete env[name];
  return env;
}

function assertExactObjectFields(value, expected, label) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const observed = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(observed) !== canonicalJson(wanted)) {
    throw new Error(`${label} has unknown or missing fields.`);
  }
}

function validateCommandFileIdentityShape(value, expectedKind) {
  assertExactObjectFields(
    value,
    [
      "schema_version",
      "kind",
      "real_path",
      "device",
      "inode",
      "size",
      "mtime_ns",
      "mode",
      "sha256",
    ],
    "Command file identity",
  );
  if (value.schema_version !== 1 ||
      value.kind !== expectedKind ||
      typeof value.real_path !== "string" ||
      !path.isAbsolute(value.real_path) ||
      !/^[0-9]+$/.test(value.device) ||
      !/^[0-9]+$/.test(value.inode) ||
      !/^[0-9]+$/.test(value.size) ||
      !/^[0-9]+$/.test(value.mtime_ns) ||
      !/^[0-9]+$/.test(value.mode) ||
      !/^[0-9a-f]{64}$/.test(value.sha256)) {
    throw new Error("Command file identity is malformed.");
  }
}

function validateCommandExecutionBindingShape(contract) {
  const value = contract.command_execution_binding;
  if (contract.action !== "command") {
    if (value !== null) {
      throw new Error(
        "Non-command action cannot carry a command execution binding.",
      );
    }
    return null;
  }
  assertExactObjectFields(
    value,
    [
      "schema_version",
      "kind",
      "base_cwd",
      "cwd",
      "environment_sha256",
      "inherited_environment_names",
      "executable",
      "direct_files",
      "binding_sha256",
    ],
    "Command execution binding",
  );
  if (value.schema_version !== 1 ||
      value.kind !== "qa_command_execution_binding" ||
      typeof value.base_cwd !== "string" ||
      !path.isAbsolute(value.base_cwd) ||
      typeof value.cwd !== "string" ||
      !path.isAbsolute(value.cwd) ||
      !/^[0-9a-f]{64}$/.test(value.environment_sha256) ||
      canonicalJson(value.inherited_environment_names) !==
        canonicalJson(COMMAND_INHERITED_ENV_NAMES) ||
      !Array.isArray(value.direct_files) ||
      !/^[0-9a-f]{64}$/.test(value.binding_sha256)) {
    throw new Error("Command execution binding is malformed.");
  }
  validateCommandFileIdentityShape(value.executable, "executable");
  let previousIndex = 0;
  for (const item of value.direct_files) {
    assertExactObjectFields(
      item,
      ["argv_index", "argument_path", "identity"],
      "Command direct file binding",
    );
    if (!Number.isSafeInteger(item.argv_index) ||
        item.argv_index <= previousIndex ||
        typeof item.argument_path !== "string" ||
        !path.isAbsolute(item.argument_path)) {
      throw new Error("Command direct file binding is malformed.");
    }
    previousIndex = item.argv_index;
    validateCommandFileIdentityShape(item.identity, "direct_input");
  }
  const unsigned = { ...value };
  delete unsigned.binding_sha256;
  if (canonicalSha256(unsigned) !== value.binding_sha256) {
    throw new Error("Command execution binding hash is invalid.");
  }
  return value;
}

function commandStatIdentity(info) {
  return {
    device: info.dev.toString(),
    inode: info.ino.toString(),
    size: info.size.toString(),
    mtime_ns: info.mtimeNs.toString(),
    mode: info.mode.toString(),
  };
}

function sameCommandStat(left, right) {
  return canonicalJson(commandStatIdentity(left)) ===
    canonicalJson(commandStatIdentity(right)) &&
    left.nlink.toString() === right.nlink.toString();
}

async function stableCommandFileIdentity(
  inputPath,
  expectedKind,
  requireExecutable,
) {
  const realPath = await fs.realpath(inputPath);
  const flags = fsConstants.O_RDONLY |
    fsConstants.O_CLOEXEC |
    (fsConstants.O_NOFOLLOW || 0);
  const handle = await fs.open(realPath, flags);
  try {
    const before = await handle.stat({ bigint: true });
    const pathBefore = await fs.lstat(realPath, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n ||
        before.size > BigInt(MAX_COMMAND_FILE_BYTES)) {
      throw new Error(
        `Command ${expectedKind} must be a bounded single-link regular file.`,
      );
    }
    if (requireExecutable && (before.mode & 0o111n) === 0n) {
      throw new Error("Bound command executable has no execute bit.");
    }
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0n;
    while (true) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        buffer.length,
        null,
      );
      if (bytesRead === 0) break;
      total += BigInt(bytesRead);
      if (total > BigInt(MAX_COMMAND_FILE_BYTES)) {
        throw new Error(`Command ${expectedKind} grew while hashing.`);
      }
      digest.update(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await fs.lstat(realPath, { bigint: true });
    if (!sameCommandStat(before, after) ||
        !sameCommandStat(before, pathBefore) ||
        !sameCommandStat(before, pathAfter)) {
      throw new Error(
        `Command ${expectedKind} changed while being hashed.`,
      );
    }
    return {
      schema_version: 1,
      kind: expectedKind,
      real_path: realPath,
      ...commandStatIdentity(before),
      sha256: digest.digest("hex"),
    };
  } finally {
    await handle.close();
  }
}

async function resolveCurrentCommandExecutable(argv0, cwd, environment) {
  const containsSeparator = argv0.includes(path.sep) ||
    (path.posix.sep !== path.sep && argv0.includes(path.posix.sep)) ||
    (path.win32.sep !== path.sep && argv0.includes(path.win32.sep));
  if (path.isAbsolute(argv0) || containsSeparator) {
    return await fs.realpath(
      path.isAbsolute(argv0) ? argv0 : path.resolve(cwd, argv0),
    );
  }
  const searchPath = typeof environment.PATH === "string"
    ? environment.PATH
    : "";
  for (const directory of searchPath.split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.resolve(directory, argv0);
    try {
      await fs.access(candidate, fsConstants.X_OK);
      return await fs.realpath(candidate);
    } catch (_) {
      // 继续检查下一个精确匹配的 PATH 目录。
    }
  }
  throw new Error(
    `Command executable is unavailable on the bound PATH: ${argv0}.`,
  );
}

async function verifyCurrentCommandExecutionBinding(
  contract,
  step,
) {
  const binding = validateCommandExecutionBindingShape(contract);
  const commandValue = step.command || step.cmd;
  if (!Array.isArray(commandValue) || !commandValue.length ||
      commandValue.some((item) => typeof item !== "string" || !item)) {
    throw new Error("Bound command argv is malformed.");
  }
  const currentBaseCwd = await fs.realpath(binding.base_cwd);
  if (currentBaseCwd !== binding.base_cwd) {
    throw new Error("Command base cwd changed after authorization.");
  }
  const expectedCwd = await fs.realpath(
    step.cwd === undefined
      ? binding.base_cwd
      : path.resolve(binding.base_cwd, String(step.cwd)),
  );
  if (expectedCwd !== binding.cwd) {
    throw new Error("Command cwd changed after authorization.");
  }
  const environment = buildCommandEnvironment(step);
  if (canonicalSha256(environment) !== binding.environment_sha256) {
    throw new Error(
      "Command child environment changed after authorization.",
    );
  }
  const executablePath = await resolveCurrentCommandExecutable(
    commandValue[0],
    binding.cwd,
    environment,
  );
  if (executablePath !== binding.executable.real_path) {
    throw new Error(
      "Command executable resolution changed after authorization.",
    );
  }
  const executableIdentity = await stableCommandFileIdentity(
    executablePath,
    "executable",
    true,
  );
  if (canonicalJson(executableIdentity) !==
      canonicalJson(binding.executable)) {
    throw new Error(
      "Command executable changed after authorization.",
    );
  }
  const args = commandValue.slice(1).map(String);
  for (const direct of binding.direct_files) {
    if (direct.argv_index >= commandValue.length) {
      throw new Error(
        "Command direct input argv index is outside the authorized argv.",
      );
    }
    const lexicalPath = path.resolve(
      binding.cwd,
      commandValue[direct.argv_index],
    );
    if (lexicalPath !== direct.argument_path) {
      throw new Error(
        "Command direct input path changed after authorization.",
      );
    }
    const realPath = await fs.realpath(direct.argument_path);
    if (realPath !== direct.identity.real_path) {
      throw new Error(
        "Command direct input target changed after authorization.",
      );
    }
    const currentIdentity = await stableCommandFileIdentity(
      realPath,
      "direct_input",
      false,
    );
    if (canonicalJson(currentIdentity) !==
        canonicalJson(direct.identity)) {
      throw new Error(
        "Command direct input changed after authorization.",
      );
    }
    args[direct.argv_index - 1] = direct.identity.real_path;
  }
  return {
    binding_sha256: binding.binding_sha256,
    command: binding.executable.real_path,
    args,
    cwd: binding.cwd,
    env: environment,
  };
}

function executionControlsSha256(
  rawStep,
  resolvedStep,
  contract,
  ctx,
  commandDispatch = null,
) {
  const trustedSpec = TRUSTED_TOOL_SPECS.get(resolvedStep.action);
  if (!trustedSpec ||
      contract.tool_spec_sha256 !== trustedSpec.specSha256 ||
      contract.idempotent !== trustedSpec.idempotent) {
    throw new Error(`Resolved invocation has no current trusted ToolSpec: ${resolvedStep.action}.`);
  }
  const timeoutEntries = Object.entries(resolvedStep)
    .filter(([key]) =>
      /(?:timeout|wait).*ms$/i.test(key) ||
      (resolvedStep.action === "wait" && key === "ms"))
    .map(([key, value]) => [key, Number(value)]);
  for (const [key, value] of timeoutEntries) {
    if (!Number.isFinite(value) || value < 0 ||
        value > trustedSpec.maxTimeoutSeconds * 1000) {
      throw new Error(
        `Resolved ${key} exceeds the trusted ToolSpec timeout boundary.`,
      );
    }
  }
  const requestedOutputLimits = [
    resolvedStep.maxStdoutChars,
    resolvedStep.maxStderrChars,
    resolvedStep.maxResponseBodyChars,
    resolvedStep.maxRequestBodyChars,
    ctx.maxArtifactChars,
  ].filter((value) => value !== undefined).map(Number);
  if (requestedOutputLimits.some((value) =>
    !Number.isFinite(value) || value < 0 ||
    value > trustedSpec.outputLimitBytes)) {
    throw new Error(
      "Resolved invocation exceeds the trusted ToolSpec output boundary.",
    );
  }
  let processControls = null;
  if (resolvedStep.action === "command") {
    if (!commandDispatch) {
      throw new Error(
        "Command execution controls require a verified execution binding.",
      );
    }
    processControls = {
      argv: [commandDispatch.command, ...commandDispatch.args],
      binding_sha256: commandDispatch.binding_sha256,
      cwd: commandDispatch.cwd,
      env_sha256: canonicalSha256(commandDispatch.env),
      shell: false,
    };
  }
  const networkControls = HIGH_RISK_NETWORK_ACTIONS.has(resolvedStep.action)
    ? {
        method: String(resolvedStep.method || "GET").toUpperCase(),
        url: absoluteHighRiskNetworkTarget(
          ctx.baseUrl,
          resolvedStep,
          `scenario.step.${rawStep.id || ""}`,
        ),
        max_redirects: 0,
      }
    : null;
  return canonicalSha256({
    schema_version: 2,
    kind: "qa_execution_controls",
    action: resolvedStep.action,
    process: processControls,
    network: networkControls,
    io_sha256: canonicalSha256({
      schema_version: 2,
      kind: "qa_secret_redacted_io_controls",
      step: structuredSecretRedactedValue(
        rawStep,
        resolvedStep,
        `scenario.step.${rawStep.id || ""}`,
      ),
      base_url: structuredSecretRedactedValue(
        ctx.rawBaseUrl,
        ctx.baseUrl,
        "plan.baseUrl",
      ),
      default_headers: structuredSecretRedactedValue(
        ctx.rawDefaultHeaders,
        ctx.defaultHeaders,
        "plan.defaultHeaders",
      ),
      extra_http_headers: structuredSecretRedactedValue(
        ctx.rawExtraHTTPHeaders,
        ctx.extraHTTPHeaders,
        "plan.extraHTTPHeaders",
      ),
    }),
    timeout_entries: timeoutEntries.sort(
      ([left], [right]) => left.localeCompare(right),
    ),
    output_limit_bytes: trustedSpec.outputLimitBytes,
    tool_max_timeout_ms: trustedSpec.maxTimeoutSeconds * 1000,
  });
}

function parseJsonItems(items) {
  return items.map((item) => {
    if (typeof item !== "string") return isObject(item) ? item : undefined;
    try {
      return JSON.parse(item);
    } catch (_) {
      return undefined;
    }
  }).filter((item) => item !== undefined);
}

function findJsonMatch(items, expectJson) {
  if (!expectJson) return undefined;
  return items.find((item) => {
    try {
      assertJson(item, expectJson);
      return true;
    } catch (_) {
      return false;
    }
  });
}

function selectExtractSource(items, spec, fallback) {
  const sourceMode = isObject(spec) ? spec.from || "matched" : "matched";
  if (sourceMode === "first") return items[0];
  if (sourceMode === "last") return items[items.length - 1];
  if (isObject(spec) && spec.matchJson) return findJsonMatch(items, spec.matchJson);
  return fallback || items[0];
}

function applyJsonExtractionSpec(record, items, extractJson, ctx, fallback, valueKey, pathsKey) {
  if (!isObject(extractJson)) throw new Error("extractJson must be an object mapping variable names to JSON paths.");

  const extracted = {};
  const extractedPaths = {};
  for (const [name, spec] of Object.entries(extractJson)) {
    const jsonPaths = isObject(spec) && Array.isArray(spec.paths)
      ? spec.paths
      : [isObject(spec) ? spec.path : spec];
    const usablePaths = jsonPaths.filter((item) => typeof item === "string" && item.trim());
    if (!usablePaths.length) {
      throw new Error(`extractJson.${name} requires a non-empty JSON path.`);
    }
    const source = selectExtractSource(items, spec, fallback);
    let value;
    let usedPath = "";
    for (const jsonPath of usablePaths) {
      value = readPath(source, jsonPath);
      if (value !== undefined) {
        usedPath = jsonPath;
        break;
      }
    }
    if (value === undefined && (!isObject(spec) || spec.required !== false)) {
      throw new Error(`extractJson.${name} could not read JSON path ${usablePaths.join(" or ")}.`);
    }
    if (value !== undefined) {
      ctx.vars[name] = value;
      extracted[name] = redact(value);
      extractedPaths[name] = usedPath;
    }
  }
  record[valueKey] = extracted;
  if (Object.keys(extractedPaths).length) record[pathsKey] = extractedPaths;
}

function applyJsonExtraction(record, items, step, ctx, fallback) {
  const extractJson = step.extractJson || step.extract_json;
  if (!extractJson) return;
  applyJsonExtractionSpec(record, items, extractJson, ctx, fallback, "extractedJson", "extractedJsonPaths");
}

function compareExpected(actual, expected) {
  if (isObject(expected) && Object.prototype.hasOwnProperty.call(expected, "op")) {
    const op = expected.op;
    const value = expected.value;
    if (op === "exists") return actual !== undefined;
    if (op === "missing") return actual === undefined;
    if (op === "notNull") return actual !== null && actual !== undefined;
    if (op === "contains") return String(actual ?? "").includes(String(value));
    if (op === "notContains") return !String(actual ?? "").includes(String(value));
    if (op === "matches") return new RegExp(String(value)).test(String(actual ?? ""));
    if (op === "gte") return Number(actual) >= Number(value);
    if (op === "lte") return Number(actual) <= Number(value);
    if (op === "gt") return Number(actual) > Number(value);
    if (op === "lt") return Number(actual) < Number(value);
    if (op === "includes" && Array.isArray(actual)) return actual.includes(value);
    if (op === "equals") return JSON.stringify(actual) === JSON.stringify(value);
    throw new Error(`Unsupported expectation operator: ${op}`);
  }
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function assertJson(body, expectJson) {
  const checkedJson = {};
  for (const [jsonPath, expectedValue] of Object.entries(expectJson || {})) {
    const actualValue = readPath(body, jsonPath);
    checkedJson[jsonPath] = redact(actualValue);
    if (!compareExpected(actualValue, expectedValue)) {
      throw new Error(`JSON path ${jsonPath} expected ${JSON.stringify(redact(expectedValue))}, got ${JSON.stringify(redact(actualValue))}`);
    }
  }
  return checkedJson;
}

function assertJsonAny(body, alternatives) {
  if (!Array.isArray(alternatives) || !alternatives.length) {
    throw new Error("expectJsonAny must be a non-empty array of JSON expectation objects.");
  }
  const errors = [];
  for (let index = 0; index < alternatives.length; index += 1) {
    try {
      const checkedJson = assertJson(body, alternatives[index]);
      return { checkedJson, alternativeIndex: index, expectation: redact(alternatives[index]) };
    } catch (error) {
      errors.push(`#${index}: ${error.message || String(error)}`);
    }
  }
  throw new Error(`No expectJsonAny alternative matched. ${errors.join(" ; ")}`);
}

function headerMap(response) {
  const headers = typeof response.headers === "function" ? response.headers() : {};
  return isObject(headers) ? headers : {};
}

function responseHeader(headers, name) {
  const wanted = String(name || "").toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

function redactHeaderValue(name, value) {
  if (value === undefined) return undefined;
  if (/authorization|cookie|token|secret|api[_-]?key/i.test(String(name || ""))) return "[REDACTED]";
  return redactString(String(value));
}

function redactHeaderMap(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) {
    out[name] = redactHeaderValue(name, value);
  }
  return out;
}

function responseHeaderFields(step) {
  return {
    capture: step.captureResponseHeaders || step.capture_response_headers,
    exact: step.expectResponseHeader || step.expect_response_header,
    contains: step.expectResponseHeaderContains || step.expect_response_header_contains,
    matches: step.expectResponseHeaderMatches || step.expect_response_header_matches,
    extract: step.extractResponseHeader || step.extract_response_header,
  };
}

function shouldInspectResponseHeaders(step) {
  const fields = responseHeaderFields(step);
  return !!(fields.capture || fields.exact || fields.contains || fields.matches || fields.extract);
}

function recordCheckedResponseHeader(record, name, value) {
  if (!record.checkedResponseHeaders) record.checkedResponseHeaders = {};
  record.checkedResponseHeaders[name] = value === undefined ? null : redactHeaderValue(name, value);
}

function inspectResponseHeaders(record, response, step, ctx) {
  if (!shouldInspectResponseHeaders(step)) return;
  const fields = responseHeaderFields(step);
  const headers = headerMap(response);
  record.responseHeaders = redactHeaderMap(headers);

  for (const [name, expected] of Object.entries(fields.exact || {})) {
    const actual = responseHeader(headers, name);
    recordCheckedResponseHeader(record, name, actual);
    if (!compareExpected(actual, expected)) {
      throw new Error(`Response header ${name} expected ${JSON.stringify(redact(expected))}, got ${JSON.stringify(redactHeaderValue(name, actual))}`);
    }
  }
  for (const [name, expected] of Object.entries(fields.contains || {})) {
    const actual = responseHeader(headers, name);
    recordCheckedResponseHeader(record, name, actual);
    if (!String(actual ?? "").includes(String(expected))) {
      throw new Error(`Response header ${name} did not contain expected text: ${expected}`);
    }
  }
  for (const [name, pattern] of Object.entries(fields.matches || {})) {
    const actual = responseHeader(headers, name);
    recordCheckedResponseHeader(record, name, actual);
    if (!new RegExp(String(pattern)).test(String(actual ?? ""))) {
      throw new Error(`Response header ${name} did not match pattern: ${pattern}`);
    }
  }

  if (fields.extract) {
    const extracted = {};
    const extractedNames = {};
    for (const [varName, spec] of Object.entries(fields.extract)) {
      const headerName = isObject(spec) ? spec.header || spec.name : spec;
      if (typeof headerName !== "string" || !headerName.trim()) {
        throw new Error(`extractResponseHeader.${varName} requires a non-empty header name.`);
      }
      const actual = responseHeader(headers, headerName);
      if (actual === undefined && (!isObject(spec) || spec.required !== false)) {
        throw new Error(`extractResponseHeader.${varName} could not read response header ${headerName}.`);
      }
      if (actual !== undefined) {
        ctx.vars[varName] = actual;
        extracted[varName] = redactHeaderValue(headerName, actual);
        extractedNames[varName] = headerName;
      }
    }
    if (Object.keys(extracted).length) record.extractedResponseHeaders = extracted;
    if (Object.keys(extractedNames).length) record.extractedResponseHeaderNames = extractedNames;
  }
}

function parseStdoutJson(stdout) {
  const text = String(stdout || "").trim();
  if (!text) throw new Error("stdout was empty; cannot evaluate stdout JSON expectations.");
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`stdout was not valid JSON: ${error.message || String(error)}`);
  }
}

function inspectStdoutJson(record, stdout, step, ctx) {
  const expectStdoutJson = step.expectStdoutJson || step.expect_stdout_json;
  const expectStdoutJsonAny = step.expectStdoutJsonAny || step.expect_stdout_json_any;
  const extractStdoutJson = step.extractStdoutJson || step.extract_stdout_json;
  if (!expectStdoutJson && !expectStdoutJsonAny && !extractStdoutJson) return;
  const body = parseStdoutJson(stdout);
  if (expectStdoutJson) {
    record.checkedStdoutJson = assertJson(body, expectStdoutJson);
  }
  if (expectStdoutJsonAny) {
    const matched = assertJsonAny(body, expectStdoutJsonAny);
    record.checkedStdoutJson = matched.checkedJson;
    record.checkedStdoutJsonAlternativeIndex = matched.alternativeIndex;
    record.checkedStdoutJsonAlternative = matched.expectation;
  }
  if (extractStdoutJson) {
    applyJsonExtractionSpec(record, [body], extractStdoutJson, ctx, body, "extractedStdoutJson", "extractedStdoutJsonPaths");
  }
}

function locatorFor(page, step) {
  if (step.selector) return page.locator(step.selector);
  if (step.text) return page.getByText(step.text, { exact: !!step.exact });
  if (step.role) return page.getByRole(step.role, { name: step.name, exact: !!step.exact });
  if (step.label) return page.getByLabel(step.label, { exact: !!step.exact });
  if (step.placeholder) return page.getByPlaceholder(step.placeholder, { exact: !!step.exact });
  if (step.testId) return page.getByTestId(step.testId);
  throw new Error("Step needs selector, text, role/name, label, placeholder, or testId.");
}

function locatorLabel(step) {
  if (step.selector) return `selector=${step.selector}`;
  if (step.text) return `text=${step.text}`;
  if (step.role) return `role=${step.role}${step.name ? ` name=${step.name}` : ""}`;
  if (step.label) return `label=${step.label}`;
  if (step.placeholder) return `placeholder=${step.placeholder}`;
  if (step.testId) return `testId=${step.testId}`;
  return "locator";
}

function clickabilityError(message, hitTest) {
  const error = new Error(message);
  error.hitTest = hitTest;
  return error;
}

async function inspectClickability(page, step) {
  const timeout = Number(step.timeoutMs || 10000);
  const locator = locatorFor(page, step).first();
  await locator.waitFor({ state: "visible", timeout });
  await locator.scrollIntoViewIfNeeded({ timeout });
  const box = await locator.boundingBox({ timeout });
  if (!box || box.width <= 0 || box.height <= 0) {
    throw new Error(`Locator ${locatorLabel(step)} is visible but has no clickable bounding box.`);
  }
  const point = {
    x: Math.round(box.x + box.width / 2),
    y: Math.round(box.y + box.height / 2),
  };
  const hitTest = await locator.evaluate(
    (element, center) => {
      const escapeCss = (value) => {
        if (window.CSS && typeof window.CSS.escape === "function") return window.CSS.escape(String(value));
        return String(value).replace(/[^A-Za-z0-9_-]/g, "\\$&");
      };
      const compactText = (node) => String(node?.innerText || node?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 160);
      const cssPath = (node) => {
        if (!node || node.nodeType !== Node.ELEMENT_NODE) return "";
        const parts = [];
        let current = node;
        while (current && current.nodeType === Node.ELEMENT_NODE && parts.length < 5) {
          const tag = current.tagName.toLowerCase();
          if (current.id) {
            parts.unshift(`${tag}#${escapeCss(current.id)}`);
            break;
          }
          const stableAttr = ["data-testid", "data-test-id", "data-onboarding", "aria-label", "role"]
            .map((name) => current.getAttribute(name) ? `[${name}="${escapeCss(current.getAttribute(name))}"]` : "")
            .find(Boolean);
          let part = `${tag}${stableAttr || ""}`;
          if (!stableAttr && current.classList.length) {
            part += Array.from(current.classList).slice(0, 3).map((name) => `.${escapeCss(name)}`).join("");
          }
          const parent = current.parentElement;
          if (parent) {
            const siblings = Array.from(parent.children).filter((child) => child.tagName === current.tagName);
            if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
          }
          parts.unshift(part);
          current = parent;
        }
        return parts.join(" > ");
      };
      const describe = (node) => {
        if (!node || node.nodeType !== Node.ELEMENT_NODE) return null;
        return {
          tag: node.tagName.toLowerCase(),
          selector: cssPath(node),
          text: compactText(node),
          id: node.id || "",
          role: node.getAttribute("role") || "",
          ariaLabel: node.getAttribute("aria-label") || "",
          dataTestId: node.getAttribute("data-testid") || node.getAttribute("data-test-id") || "",
          dataOnboarding: node.getAttribute("data-onboarding") || "",
        };
      };

      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);
      const top = document.elementFromPoint(center.x, center.y);
      const receivesPointerEvents = !!top && (top === element || element.contains(top));
      return {
        center,
        rect: {
          x: Math.round(rect.x),
          y: Math.round(rect.y),
          width: Math.round(rect.width),
          height: Math.round(rect.height),
        },
        viewport: { width: window.innerWidth, height: window.innerHeight },
        target: describe(element),
        topElement: describe(top),
        blocker: receivesPointerEvents ? null : describe(top),
        receivesPointerEvents,
        disabled: Boolean(element.disabled || element.matches(":disabled")),
        ariaDisabled: element.getAttribute("aria-disabled") === "true" || Boolean(element.closest('[aria-disabled="true"]')),
        inert: Boolean(element.closest("[inert]")),
        style: {
          pointerEvents: style.pointerEvents,
          visibility: style.visibility,
          display: style.display,
          opacity: style.opacity,
        },
      };
    },
    point
  );

  if (hitTest.disabled) throw clickabilityError(`Locator ${locatorLabel(step)} is disabled.`, hitTest);
  if (hitTest.ariaDisabled && step.allowAriaDisabled !== true) throw clickabilityError(`Locator ${locatorLabel(step)} has aria-disabled=true.`, hitTest);
  if (hitTest.inert) throw clickabilityError(`Locator ${locatorLabel(step)} is inside an inert subtree.`, hitTest);
  if (hitTest.style?.pointerEvents === "none") throw clickabilityError(`Locator ${locatorLabel(step)} has pointer-events:none.`, hitTest);
  if (!hitTest.receivesPointerEvents) {
    const blocker = hitTest.blocker?.selector || hitTest.topElement?.selector || "unknown element";
    const blockerText = hitTest.blocker?.text ? ` text=${JSON.stringify(hitTest.blocker.text)}` : "";
    throw clickabilityError(`Locator ${locatorLabel(step)} is visible but center hit-test is blocked by ${blocker}${blockerText}.`, hitTest);
  }

  try {
    await locator.click({ timeout, trial: true });
  } catch (error) {
    throw clickabilityError(error && error.message ? error.message : String(error), hitTest);
  }
  hitTest.actionability = "trial-click-passed";
  return hitTest;
}

function responseMatchesStep(response, step, ctx) {
  const url = response.url();
  const method = response.request().method().toUpperCase();
  const expectedMethod = step.responseMethod || (step.action === "clickAndWaitForResponse" ? step.method : undefined);
  if (expectedMethod && method !== String(expectedMethod).toUpperCase()) return false;
  if (step.responseUrl && url !== String(step.responseUrl)) return false;
  if (step.responsePathTemplate && url !== resolveUrl(ctx.baseUrl, { pathTemplate: step.responsePathTemplate, encodePathVars: step.encodePathVars }, ctx)) return false;
  if (step.responsePath && url !== resolveUrl(ctx.baseUrl, { path: step.responsePath }, ctx)) return false;
  if (step.responseUrlContains && !url.includes(String(step.responseUrlContains))) return false;
  if (step.responseUrlPattern && !new RegExp(String(step.responseUrlPattern)).test(url)) return false;
  if (step.urlContains && !url.includes(String(step.urlContains))) return false;
  if (step.urlPattern && !new RegExp(String(step.urlPattern)).test(url)) return false;
  if (step.matchStatus !== undefined && response.status() !== Number(step.matchStatus)) return false;
  return true;
}

function requestMatchesStep(request, step, ctx) {
  const url = typeof request.url === "function" ? request.url() : String(request.url || "");
  const method = (typeof request.method === "function" ? request.method() : String(request.method || "")).toUpperCase();
  const expectedMethod = step.method ? String(step.method).toUpperCase() : "";
  if (expectedMethod && method !== expectedMethod) return false;
  if (step.url && url !== String(step.url)) return false;
  if (step.pathTemplate && url !== resolveUrl(ctx.baseUrl, { pathTemplate: step.pathTemplate, encodePathVars: step.encodePathVars }, ctx)) return false;
  if (step.path && url !== resolveUrl(ctx.baseUrl, { path: step.path }, ctx)) return false;
  if (step.urlContains && !url.includes(String(step.urlContains))) return false;
  if (step.responseUrlContains && !url.includes(String(step.responseUrlContains))) return false;
  if (step.urlPattern && !new RegExp(String(step.urlPattern)).test(url)) return false;
  if (step.responseUrlPattern && !new RegExp(String(step.responseUrlPattern)).test(url)) return false;
  return true;
}

async function captureHttpResponse(record, response, step, ctx, scenario, artifactName) {
  if ((step.captureRequestBody || step.capture_request_body) && typeof response.request === "function") {
    const request = response.request();
    const postData = request && typeof request.postData === "function" ? request.postData() : undefined;
    await captureRequestBody(record, postData, step, ctx, scenario, artifactName);
  }
  record.url = redactString(response.url());
  record.method = typeof response.request === "function"
    ? response.request().method().toUpperCase()
    : String(step.method || "GET").toUpperCase();
  record.statusCode = response.status();
  inspectResponseHeaders(record, response, step, ctx);
  const expectJsonAny = step.expectJsonAny || step.expect_json_any;
  const expectStatusAny = step.expectStatusAny || step.expect_status_any;
  const needsBodyArtifact = step.expectResponseTextContains || step.expectResponseTextNotContains || step.expectJson || expectJsonAny || step.extractJson || step.extract_json;
  const shouldReadBody = needsBodyArtifact || step.captureBody || step.captureBodyFile;
  if (shouldReadBody) {
    const text = await response.text();
    if (needsBodyArtifact || step.captureBody !== false || step.captureBodyFile) {
      record.bodyPreview = boundedText(text, Number(step.maxBodyChars || 800));
      record.bodyPath = await writeTextArtifact(ctx, `${scenario.id}-${artifactName}-body`, text);
    }
    if (step.expectResponseTextContains && !text.includes(step.expectResponseTextContains)) {
      throw new Error(`Response text did not contain expected text: ${step.expectResponseTextContains}`);
    }
    if (step.expectResponseTextContains) {
      record.responseTextContainsMatched = String(step.expectResponseTextContains);
    }
    if (step.expectResponseTextNotContains && text.includes(step.expectResponseTextNotContains)) {
      throw new Error(`Response text contained forbidden text: ${step.expectResponseTextNotContains}`);
    }
    if (step.expectResponseTextNotContains) {
      record.responseTextNotContainsMatched = String(step.expectResponseTextNotContains);
    }
    if (step.expectJson || expectJsonAny || step.extractJson || step.extract_json) {
      let body;
      try {
        body = JSON.parse(text);
      } catch (error) {
        throw new Error(`Response was not valid JSON: ${error.message || String(error)}`);
      }
      if (step.expectJson) {
        record.checkedJson = assertJson(body, step.expectJson);
      }
      if (expectJsonAny) {
        const matched = assertJsonAny(body, expectJsonAny);
        record.checkedJson = matched.checkedJson;
        record.checkedJsonAlternativeIndex = matched.alternativeIndex;
        record.checkedJsonAlternative = matched.expectation;
      }
      if (step.extractJson || step.extract_json) {
        applyJsonExtraction(record, [body], step, ctx, body);
      }
    }
  }
  if (step.expectStatus !== undefined && response.status() !== Number(step.expectStatus)) {
    throw new Error(`Expected status ${step.expectStatus}, got ${response.status()}`);
  }
  if (expectStatusAny !== undefined) {
    const allowedStatuses = Array.isArray(expectStatusAny) ? expectStatusAny.map(Number) : [];
    record.expectedStatusAny = allowedStatuses;
    if (!allowedStatuses.includes(response.status())) {
      throw new Error(`Expected one of statuses ${allowedStatuses.join(", ")}, got ${response.status()}`);
    }
  }
}

function shouldInspectRequestBody(step) {
  return !!(
    step.captureRequestBody ||
    step.capture_request_body ||
    step.expectRequestTextContains ||
    step.expect_request_text_contains ||
    step.expectRequestTextNotContains ||
    step.expect_request_text_not_contains ||
    step.expectRequestJson ||
    step.expect_request_json
  );
}

async function captureRequestBody(record, bodyText, step, ctx, scenario, artifactName) {
  if (!shouldInspectRequestBody(step)) return;
  const expectTextContains = step.expectRequestTextContains || step.expect_request_text_contains;
  const expectTextNotContains = step.expectRequestTextNotContains || step.expect_request_text_not_contains;
  const expectRequestJson = step.expectRequestJson || step.expect_request_json;
  if (bodyText === undefined || bodyText === null || bodyText === "") {
    record.requestBodyCaptured = false;
    if (expectTextContains || expectTextNotContains || expectRequestJson) {
      throw new Error("Request body was empty; cannot evaluate request body expectations.");
    }
    return;
  }
  const text = typeof bodyText === "string" ? bodyText : JSON.stringify(bodyText);
  record.requestBodyCaptured = true;
  record.requestBodyPreview = boundedText(text, Number(step.maxRequestBodyChars || 800));
  if (step.captureRequestBody || step.capture_request_body) {
    record.requestBodyPath = await writeTextArtifact(ctx, `${scenario.id}-${artifactName}-request-body`, text);
  }
  if (expectTextContains && !text.includes(String(expectTextContains))) {
    throw new Error(`Request body did not contain expected text: ${expectTextContains}`);
  }
  if (expectTextContains) record.requestTextContainsMatched = String(expectTextContains);
  if (expectTextNotContains && text.includes(String(expectTextNotContains))) {
    throw new Error(`Request body contained forbidden text: ${expectTextNotContains}`);
  }
  if (expectTextNotContains) record.requestTextNotContainsMatched = String(expectTextNotContains);
  if (expectRequestJson) {
    let body;
    try {
      body = JSON.parse(text);
    } catch (error) {
      throw new Error(`Request body was not valid JSON: ${error.message || String(error)}`);
    }
    record.checkedRequestJson = assertJson(body, expectRequestJson);
  }
}

function buildApiRequest(step, ctx) {
  const url = resolveUrl(ctx.baseUrl, step, ctx);
  const method = String(step.method || "GET").toUpperCase();
  const headers = { ...(ctx.defaultHeaders || {}), ...(step.headers || {}) };
  const requestOptions = {
    method,
    headers,
    timeout: step.requestTimeoutMs || step.apiTimeoutMs || step.timeoutMs || 15000,
    maxRedirects: 0,
  };
  if (step.json !== undefined) {
    requestOptions.data = JSON.stringify(step.json);
    if (!Object.keys(headers).some((key) => key.toLowerCase() === "content-type")) {
      headers["content-type"] = "application/json";
    }
  } else if (step.body !== undefined) {
    requestOptions.data = typeof step.body === "string" ? step.body : JSON.stringify(step.body);
  }
  return { url, requestOptions };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runPollApi(record, context, step, ctx, scenario) {
  const intervalMs = Math.max(50, Number(step.pollIntervalMs || step.intervalMs || 1000));
  const timeoutMs = Math.max(intervalMs, Number(step.pollTimeoutMs || step.timeoutMs || 30000));
  const maxAttempts = Math.max(1, Number(step.maxAttempts || Math.ceil(timeoutMs / intervalMs) + 1));
  const deadline = Date.now() + timeoutMs;
  const attempts = [];
  let lastError = "";

  for (let attempt = 1; attempt <= maxAttempts && Date.now() <= deadline; attempt += 1) {
    const attemptRecord = {};
    try {
      const { url, requestOptions } = buildApiRequest(step, ctx);
      await captureRequestBody(attemptRecord, requestOptions.data, step, ctx, scenario, `${step.id || "poll-api"}-attempt-${attempt}`);
      const response = await context.request.fetch(url, requestOptions);
      await captureHttpResponse(attemptRecord, response, step, ctx, scenario, `${step.id || "poll-api"}-attempt-${attempt}`);
      Object.assign(record, attemptRecord);
      record.pollAttemptCount = attempt;
      record.pollIntervalMs = intervalMs;
      record.pollTimeoutMs = timeoutMs;
      record.pollMatched = true;
      attempts.push({
        attempt,
        status: "matched",
        url: attemptRecord.url,
        statusCode: attemptRecord.statusCode,
        checkedResponseHeaders: attemptRecord.checkedResponseHeaders,
        checkedJson: attemptRecord.checkedJson,
        checkedJsonAlternativeIndex: attemptRecord.checkedJsonAlternativeIndex,
      });
      record.pollAttempts = attempts;
      return;
    } catch (error) {
      lastError = error && error.message ? error.message : String(error);
      attempts.push({
        attempt,
        status: "not_matched",
        url: attemptRecord.url,
        statusCode: attemptRecord.statusCode,
        checkedResponseHeaders: attemptRecord.checkedResponseHeaders,
        checkedJson: attemptRecord.checkedJson,
        error: boundedText(lastError, 500),
      });
      if (attempt < maxAttempts && Date.now() + intervalMs <= deadline) {
        await sleep(intervalMs);
      }
    }
  }

  record.pollAttemptCount = attempts.length;
  record.pollIntervalMs = intervalMs;
  record.pollTimeoutMs = timeoutMs;
  record.pollMatched = false;
  record.pollAttempts = attempts;
  throw new Error(`pollApi did not satisfy expectations after ${attempts.length} attempt(s). Last error: ${lastError}`);
}

async function writeTextArtifact(ctx, name, text) {
  const file = path.join(ctx.evidenceDir, `${safeName(name)}.txt`);
  await fs.writeFile(file, boundedText(text, ctx.maxArtifactChars), "utf-8");
  return file;
}

async function runCommand(step, ctx, verifiedDispatch = null) {
  const timeoutMs = Number(step.timeoutMs || 30000);
  const commandValue = step.command || step.cmd;
  if (!commandValue) throw new Error("command step requires command or cmd.");

  const useShell = verifiedDispatch
    ? false
    : step.shell === true || typeof commandValue === "string";
  const command = verifiedDispatch
    ? verifiedDispatch.command
    : Array.isArray(commandValue)
      ? commandValue[0]
      : String(commandValue);
  const args = verifiedDispatch
    ? verifiedDispatch.args
    : Array.isArray(commandValue)
      ? commandValue.slice(1).map(String)
      : [];
  const cwd = verifiedDispatch
    ? verifiedDispatch.cwd
    : step.cwd
      ? path.resolve(String(step.cwd))
      : process.cwd();
  const env = verifiedDispatch
    ? verifiedDispatch.env
    : buildCommandEnvironment(step);

  return await new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    const maxOutputChars = Math.max(Number(ctx.maxArtifactChars || 10000), 1000);
    const detached = process.platform !== "win32";
    const child = spawn(command, args, { cwd, env, shell: useShell, detached });
    let killTimer;
    let forceResolveTimer;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      clearTimeout(forceResolveTimer);
      resolve(payload);
    };
    const appendBounded = (current, chunk) => {
      const combined = current + chunk.toString();
      if (combined.length <= maxOutputChars) return combined;
      return `[truncated to last ${maxOutputChars} chars]\n${combined.slice(-maxOutputChars)}`;
    };
    const signalTree = (signal) => {
      try {
        if (detached && child.pid) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch (_) {
        // 进程可能已在信号发出前退出，由 close/error 事件收口。
      }
    };
    const timer = setTimeout(() => {
      if (!settled) {
        timedOut = true;
        signalTree("SIGTERM");
        killTimer = setTimeout(() => signalTree("SIGKILL"), 1000);
        forceResolveTimer = setTimeout(
          () => finish({ exitCode: null, timedOut: true, stdout, stderr }),
          3000,
        );
      }
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.on("error", (error) => {
      finish({ exitCode: null, timedOut, error: error.message || String(error), stdout, stderr });
    });
    child.on("close", (code) => {
      finish({ exitCode: code, timedOut, stdout, stderr });
    });
  });
}

async function runWebSocketProbe(page, url, step) {
  const timeoutMs = Number(step.timeoutMs || 15000);
  const waitMs = Number(step.waitMs || Math.min(timeoutMs, 1000));
  const finishOnText = step.finishOnMessageTextContains || step.finishOnText || step.expectMessageTextContains || "";
  const finishDelayMs = Number(step.finishDelayMs || 100);
  const failOnJsonTypes = step.failOnJsonTypes === undefined ? ["error"] : Array.isArray(step.failOnJsonTypes) ? step.failOnJsonTypes.map(String) : [];
  const finishOnJsonTypes = Array.isArray(step.finishOnJsonTypes) ? step.finishOnJsonTypes.map(String) : [];
  const sends = Array.isArray(step.send) ? step.send : step.send === undefined ? [] : [step.send];
  return await page.evaluate(
    ({ url: wsUrl, sends: messagesToSend, timeoutMs: timeout, waitMs: wait, finishOnText, finishDelayMs, failOnJsonTypes, finishOnJsonTypes }) =>
      new Promise((resolve) => {
        const messages = [];
        const sent = [];
        const errors = [];
        let opened = false;
        let closed = false;
        let closeCode = null;
        let done = false;
        let finishDelayTimer = null;

        function finish() {
          if (done) return;
          done = true;
          clearTimeout(timeoutTimer);
          clearTimeout(waitTimer);
          clearTimeout(finishDelayTimer);
          try {
            if (socket && socket.readyState === WebSocket.OPEN) socket.close();
          } catch (_) {}
          resolve({ opened, closed, closeCode, sent, messages, errors });
        }

        function inspectPayload(payload) {
          let parsed = null;
          try {
            parsed = JSON.parse(payload);
          } catch (_) {
            return;
          }
          const type = parsed && typeof parsed.type === "string" ? parsed.type : "";
          if (!type) return;
          if (failOnJsonTypes.includes(type)) {
            const detail = parsed.message || parsed.error || parsed.code || payload;
            errors.push(`WebSocket JSON ${type}: ${detail}`);
            finishDelayTimer = setTimeout(finish, finishDelayMs);
          } else if (finishOnJsonTypes.includes(type)) {
            finishDelayTimer = setTimeout(finish, finishDelayMs);
          }
        }

        let socket;
        const timeoutTimer = setTimeout(() => {
          errors.push(`Timed out after ${timeout}ms`);
          finish();
        }, timeout);
        const waitTimer = setTimeout(finish, wait);

        try {
          socket = new WebSocket(wsUrl);
          socket.addEventListener("open", () => {
            opened = true;
            for (const item of messagesToSend) {
              const payload = typeof item === "string" ? item : JSON.stringify(item);
              socket.send(payload);
              sent.push(payload);
            }
          });
          socket.addEventListener("message", (event) => {
            const payload = String(event.data);
            messages.push(payload);
            if (finishOnText && payload.includes(finishOnText)) {
              finishDelayTimer = setTimeout(finish, finishDelayMs);
            }
            inspectPayload(payload);
          });
          socket.addEventListener("close", (event) => {
            closed = true;
            closeCode = event.code;
          });
          socket.addEventListener("error", () => {
            errors.push("WebSocket error event");
          });
        } catch (error) {
          errors.push(error && error.message ? error.message : String(error));
          finish();
        }
      }),
    { url, sends, timeoutMs, waitMs, finishOnText, finishDelayMs, failOnJsonTypes, finishOnJsonTypes },
  );
}

async function runSseProbe(page, url, step) {
  const timeoutMs = Number(step.timeoutMs || 15000);
  const waitMs = Number(step.waitMs || Math.min(timeoutMs, 1000));
  const finishOnText = step.finishOnMessageTextContains || step.finishOnText || step.expectMessageTextContains || "";
  const finishDelayMs = Number(step.finishDelayMs || 100);
  const failOnJsonTypes = step.failOnJsonTypes === undefined ? ["error"] : Array.isArray(step.failOnJsonTypes) ? step.failOnJsonTypes.map(String) : [];
  const finishOnJsonTypes = Array.isArray(step.finishOnJsonTypes) ? step.finishOnJsonTypes.map(String) : [];
  return await page.evaluate(
    ({ url: sseUrl, timeoutMs: timeout, waitMs: wait, eventName, finishOnText, finishDelayMs, failOnJsonTypes, finishOnJsonTypes }) =>
      new Promise((resolve) => {
        const messages = [];
        const errors = [];
        let opened = false;
        let done = false;
        let finishDelayTimer = null;

        function finish() {
          if (done) return;
          done = true;
          clearTimeout(timeoutTimer);
          clearTimeout(waitTimer);
          clearTimeout(finishDelayTimer);
          try {
            if (source) source.close();
          } catch (_) {}
          resolve({ opened, messages, errors });
        }

        function inspectPayload(payload) {
          let parsed = null;
          try {
            parsed = JSON.parse(payload);
          } catch (_) {
            return;
          }
          const type = parsed && typeof parsed.type === "string" ? parsed.type : "";
          if (!type) return;
          if (failOnJsonTypes.includes(type)) {
            const detail = parsed.message || parsed.error || parsed.code || payload;
            errors.push(`SSE JSON ${type}: ${detail}`);
            finishDelayTimer = setTimeout(finish, finishDelayMs);
          } else if (finishOnJsonTypes.includes(type)) {
            finishDelayTimer = setTimeout(finish, finishDelayMs);
          }
        }

        let source;
        const timeoutTimer = setTimeout(() => {
          errors.push(`Timed out after ${timeout}ms`);
          finish();
        }, timeout);
        const waitTimer = setTimeout(finish, wait);

        try {
          source = new EventSource(sseUrl);
          source.addEventListener("open", () => {
            opened = true;
          });
          source.addEventListener("error", () => {
            errors.push("EventSource error event");
          });
          const handler = (event) => {
            const payload = String(event.data);
            messages.push(payload);
            if (finishOnText && payload.includes(finishOnText)) {
              finishDelayTimer = setTimeout(finish, finishDelayMs);
            }
            inspectPayload(payload);
          };
          if (eventName) source.addEventListener(eventName, handler);
          source.addEventListener("message", handler);
        } catch (error) {
          errors.push(error && error.message ? error.message : String(error));
          finish();
        }
      }),
    { url, timeoutMs, waitMs, eventName: step.eventName || "", finishOnText, finishDelayMs, failOnJsonTypes, finishOnJsonTypes },
  );
}

async function runStep(page, context, scenario, rawStep, ctx) {
  let step = rawStep;
  let dispatchToken = null;
  let commandDispatch = null;
  const startedAt = new Date().toISOString();
  const previousStepStartedAt = (ctx.lastStepStartedAtByScenario && ctx.lastStepStartedAtByScenario[scenario.id]) || startedAt;
  if (ctx.lastStepStartedAtByScenario) ctx.lastStepStartedAtByScenario[scenario.id] = startedAt;
  const record = {
    scenarioId: scenario.id,
    stepId: rawStep.id || "",
    testIds: rawStep.testIds || rawStep.test_ids || [],
    requirementIds: rawStep.requirementIds || rawStep.requirement_ids || [],
    action: rawStep.action,
    title: rawStep.title || "",
    evidenceType: rawStep.evidenceType || rawStep.evidence_type || "",
    proves: rawStep.proves || "",
    startedAt,
    status: "passed",
  };
  if (!record.evidenceType && rawStep.action === "cleanupApi") {
    record.evidenceType = "cleanup";
  }

  try {
    step = resolveRuntimeRefs(
      resolveEnvRefs(
        rawStep,
        `scenario.${scenario.id}.step.${rawStep.id || ""}`,
      ),
      ctx,
      `scenario.${scenario.id}.step.${rawStep.id || ""}`,
    );
    if (!isObject(step) ||
        step.id !== rawStep.id ||
        step.action !== rawStep.action) {
      throw new Error(
        `Resolved action identity changed for ${scenario.id}/${rawStep.id || ""}.`,
      );
    }
    if (step.action === "command") {
      validateResolvedCommandBoundary(rawStep, step);
    }
    if (HIGH_RISK_NETWORK_ACTIONS.has(step.action)) {
      for (const field of ["method", "url", "path"]) {
        if (canonicalSha256(rawStep[field] ?? null) !==
            canonicalSha256(step[field] ?? null)) {
          throw new Error(
            `Resolved high-risk network target field changed dynamically: step.${field}.`,
          );
        }
      }
      absoluteHighRiskNetworkTarget(
        ctx.baseUrl,
        step,
        `scenario.${scenario.id}.step.${rawStep.id || ""}`,
      );
    }
    const trustedSpec = TRUSTED_TOOL_SPECS.get(step.action);
    if (!trustedSpec) {
      throw new Error(
        `Resolved action is not in the current trusted ToolRegistry: ${step.action}.`,
      );
    }
    const runtimeContract = ctx.actionJournal
      ? ctx.actionJournal.contract(scenario, rawStep)
      : {
          tool_spec_sha256: trustedSpec.specSha256,
          idempotent: trustedSpec.idempotent,
        };
    if (ctx.actionJournal) {
      if (step.action === "command") {
        commandDispatch =
          await verifyCurrentCommandExecutionBinding(
            runtimeContract,
            step,
          );
      }
      const controlsSha256 = executionControlsSha256(
        rawStep,
        step,
        runtimeContract,
        ctx,
        commandDispatch,
      );
      dispatchToken = await ctx.actionJournal.intent(
        scenario,
        rawStep,
        step,
        controlsSha256,
      );
    }
    if (step.action === "goto") {
      const url = resolveUrl(ctx.baseUrl, step, ctx);
      await page.goto(url, { waitUntil: step.waitUntil || "domcontentloaded", timeout: step.timeoutMs || 30000 });
      record.url = redactString(page.url());
    } else if (step.action === "setLocalStorage") {
      const url = resolveUrl(ctx.baseUrl, { url: step.origin, path: step.path || "/" }, ctx);
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: step.timeoutMs || 30000 });
      await page.evaluate((values) => {
        for (const [key, value] of Object.entries(values || {})) {
          window.localStorage.setItem(key, typeof value === "string" ? value : JSON.stringify(value));
        }
      }, step.values || {});
      record.url = redactString(page.url());
      record.keys = Object.keys(step.values || {});
    } else if (step.action === "addCookies") {
      const cookies = Array.isArray(step.cookies) ? step.cookies : [step.cookie].filter(Boolean);
      await context.addCookies(cookies);
      record.cookieCount = cookies.length;
    } else if (step.action === "clickText") {
      await page.getByText(step.text, { exact: !!step.exact }).click({ timeout: step.timeoutMs || 10000 });
    } else if (step.action === "clickRole") {
      await page.getByRole(step.role, { name: step.name, exact: !!step.exact }).click({ timeout: step.timeoutMs || 10000 });
    } else if (step.action === "click") {
      await locatorFor(page, step).click({ timeout: step.timeoutMs || 10000, force: !!step.force });
    } else if (step.action === "fillLabel") {
      await page.getByLabel(step.label, { exact: !!step.exact }).fill(String(step.value ?? ""), { timeout: step.timeoutMs || 10000 });
    } else if (step.action === "fillPlaceholder") {
      await page.getByPlaceholder(step.placeholder, { exact: !!step.exact }).fill(String(step.value ?? ""), { timeout: step.timeoutMs || 10000 });
    } else if (step.action === "fill") {
      await locatorFor(page, step).fill(String(step.value ?? ""), { timeout: step.timeoutMs || 10000 });
    } else if (step.action === "press") {
      await page.keyboard.press(step.key);
    } else if (step.action === "wait") {
      await page.waitForTimeout(step.ms || 500);
    } else if (step.action === "waitForLoadState") {
      await page.waitForLoadState(step.state || "networkidle", { timeout: step.timeoutMs || 30000 });
    } else if (step.action === "waitForResponse") {
      const response = await page.waitForResponse((resp) => responseMatchesStep(resp, step, ctx), { timeout: step.timeoutMs || 15000 });
      await captureHttpResponse(record, response, step, ctx, scenario, step.id || "response");
    } else if (step.action === "expectText") {
      const locator = page.getByText(step.text, { exact: !!step.exact });
      await locator.first().waitFor({ state: "visible", timeout: step.timeoutMs || 10000 });
      record.count = await locator.count();
    } else if (step.action === "expectAnyText") {
      const texts = Array.isArray(step.texts) ? step.texts : [];
      if (!texts.length) throw new Error("expectAnyText requires non-empty texts array.");
      const deadline = Date.now() + Number(step.timeoutMs || 10000);
      const errors = [];
      let matched = "";
      for (const text of texts) {
        const remaining = Math.max(250, deadline - Date.now());
        try {
          const locator = page.getByText(String(text), { exact: !!step.exact });
          await locator.first().waitFor({ state: "visible", timeout: remaining });
          matched = String(text);
          record.count = await locator.count();
          break;
        } catch (error) {
          errors.push(`${text}: ${error.message || String(error)}`);
        }
      }
      if (!matched) throw new Error(`None of the expected texts were visible: ${texts.join(" | ")}. ${errors.join(" ; ")}`);
      record.matchedText = matched;
    } else if (step.action === "expectVisible") {
      await locatorFor(page, step).waitFor({ state: "visible", timeout: step.timeoutMs || 10000 });
    } else if (step.action === "expectClickable") {
      record.url = redactString(page.url());
      record.locator = locatorLabel(step);
      record.hitTest = await inspectClickability(page, step);
    } else if (step.action === "clickAndWaitForResponse") {
      record.pageUrl = redactString(page.url());
      record.locator = locatorLabel(step);
      record.hitTest = await inspectClickability(page, step);
      const responseTimeout = Number(step.responseTimeoutMs || step.timeoutMs || 15000);
      const responsePromise = page.waitForResponse((resp) => responseMatchesStep(resp, step, ctx), { timeout: responseTimeout });
      try {
        await locatorFor(page, step).click({ timeout: step.clickTimeoutMs || step.timeoutMs || 10000, force: !!step.force });
      } catch (error) {
        responsePromise.catch(() => {});
        throw error;
      }
      const response = await responsePromise;
      record.responseAfterClick = true;
      await captureHttpResponse(record, response, step, ctx, scenario, step.id || "click-response");
    } else if (step.action === "expectHidden") {
      await locatorFor(page, step).waitFor({ state: "hidden", timeout: step.timeoutMs || 10000 });
    } else if (step.action === "expectLocatorCount") {
      const count = await locatorFor(page, step).count();
      record.count = count;
      if (step.expectCount !== undefined && count !== Number(step.expectCount)) throw new Error(`Expected count ${step.expectCount}, got ${count}`);
      if (step.expectAtLeast !== undefined && count < Number(step.expectAtLeast)) throw new Error(`Expected count >= ${step.expectAtLeast}, got ${count}`);
      if (step.expectAtMost !== undefined && count > Number(step.expectAtMost)) throw new Error(`Expected count <= ${step.expectAtMost}, got ${count}`);
    } else if (step.action === "expectUrlContains") {
      const current = page.url();
      if (!current.includes(step.text)) throw new Error(`URL does not contain ${step.text}: ${current}`);
      record.url = redactString(current);
    } else if (step.action === "expectNoConsoleErrors") {
      const ignore = (step.ignorePatterns || []).map((item) => new RegExp(String(item)));
      const errors = ctx.result.console.filter((msg) => msg.type === "error" && !ignore.some((pattern) => pattern.test(msg.text)));
      if (errors.length) throw new Error(`Console errors present: ${errors.length}`);
      record.checkedConsoleErrors = 0;
      record.ignoredConsoleErrors = ctx.result.console.filter((msg) => msg.type === "error").length - errors.length;
    } else if (step.action === "expectNoRequestFailures") {
      const ignore = (step.ignorePatterns || []).map((item) => new RegExp(String(item)));
      const failures = ctx.result.requestFailures.filter((item) => {
        const haystack = `${item.method || ""} ${item.url || ""} ${item.failure || ""}`;
        return !ignore.some((pattern) => pattern.test(haystack));
      });
      if (failures.length) throw new Error(`Request failures present: ${failures.length}`);
      record.checkedRequestFailures = 0;
      record.ignoredRequestFailures = ctx.result.requestFailures.length - failures.length;
    } else if (step.action === "expectNoRequest") {
      await page.waitForTimeout(step.waitMs || 500);
      const ignore = (step.ignorePatterns || []).map((item) => new RegExp(String(item)));
      const observationStartedAt = step.sinceStartedAt || previousStepStartedAt;
      const observationStartedMs = Date.parse(observationStartedAt);
      const scopedRequests = Number.isFinite(observationStartedMs)
        ? (ctx.result.requests || []).filter((item) => {
          const requestTime = Date.parse(item.time || "");
          return Number.isFinite(requestTime) && requestTime >= observationStartedMs;
        })
        : (ctx.result.requests || []);
      const matches = scopedRequests.filter((item) => {
        const haystack = `${item.method || ""} ${item.url || ""}`;
        return requestMatchesStep(item, step, ctx) && !ignore.some((pattern) => pattern.test(haystack));
      });
      record.checkedNoRequest = 0;
      record.observationStartedAt = observationStartedAt;
      record.ignoredRequests = scopedRequests.filter((item) => {
        const haystack = `${item.method || ""} ${item.url || ""}`;
        return requestMatchesStep(item, step, ctx) && ignore.some((pattern) => pattern.test(haystack));
      }).length;
      record.checkedRequestMethod = step.method ? String(step.method).toUpperCase() : "";
      record.checkedRequestTarget = step.path || step.pathTemplate || step.url || step.urlContains || step.urlPattern || step.responseUrlContains || step.responseUrlPattern || "";
      if (matches.length) {
        record.matchingRequests = matches.slice(0, Number(step.maxMatches || 5)).map((item) => ({
          method: item.method,
          url: item.url,
          resourceType: item.resourceType,
          time: item.time,
        }));
        throw new Error(`Forbidden request observed: ${matches.length}`);
      }
    } else if (step.action === "expectNoFailedResponses") {
      const ignore = (step.ignorePatterns || []).map((item) => new RegExp(String(item)));
      const failures = ctx.result.failedResponses.filter((item) => {
        const haystack = `${item.status || ""} ${item.url || ""}`;
        return !ignore.some((pattern) => pattern.test(haystack));
      });
      if (failures.length) throw new Error(`Failed HTTP responses present: ${failures.length}`);
      record.checkedFailedResponses = 0;
      record.ignoredFailedResponses = ctx.result.failedResponses.length - failures.length;
    } else if (step.action === "dismissIfPresent") {
      const locators = Array.isArray(step.locators) ? step.locators : [step].filter((item) => item.selector || item.text || item.role || item.label || item.placeholder || item.testId);
      let dismissed = false;
      const attempts = [];
      for (const item of locators) {
        try {
          const locator = locatorFor(page, item);
          const count = await locator.count();
          attempts.push({ locator: item.selector || item.text || item.name || item.label || item.placeholder || item.testId || item.role || "locator", count });
          if (count > 0) {
            await locator.first().click({ timeout: step.timeoutMs || 2500, force: !!step.force });
            dismissed = true;
            await page.waitForTimeout(step.afterMs || 250);
            if (step.once !== false) break;
          }
        } catch (error) {
          attempts.push({ locator: item.selector || item.text || item.name || item.label || item.placeholder || item.testId || item.role || "locator", error: error.message || String(error) });
        }
      }
      record.dismissed = dismissed;
      record.attempts = attempts;
    } else if (step.action === "screenshot") {
      const file = path.join(ctx.screenshotDir, `${scenario.id}-${safeName(step.name || step.id || "screenshot")}.png`);
      if (step.selector || step.text || step.role || step.label || step.placeholder || step.testId) {
        await locatorFor(page, step).screenshot({ path: file, timeout: step.timeoutMs || 10000 });
      } else {
        await page.screenshot({ path: file, fullPage: step.fullPage !== false });
      }
      record.screenshot = file;
    } else if (step.action === "api" || step.action === "cleanupApi") {
      if (step.action === "cleanupApi") record.cleanupAttempted = true;
      const { url, requestOptions } = buildApiRequest(step, ctx);
      await captureRequestBody(record, requestOptions.data, step, ctx, scenario, step.id || "api");
      const response = await context.request.fetch(url, requestOptions);
      await captureHttpResponse(record, response, step, ctx, scenario, step.id || "api");
    } else if (step.action === "pollApi") {
      await runPollApi(record, context, step, ctx, scenario);
    } else if (step.action === "websocket") {
      const url = resolveWsUrl(ctx.baseUrl, step, ctx);
      const wsResult = await runWebSocketProbe(page, url, step);
      record.url = redactString(url);
      record.opened = wsResult.opened;
      record.closed = wsResult.closed;
      record.closeCode = wsResult.closeCode;
      record.messageCount = wsResult.messages.length;
      record.sentCount = wsResult.sent.length;
      record.messagesPreview = wsResult.messages.slice(0, Number(step.maxMessages || 20)).map((msg) => boundedText(msg, Number(step.maxMessageChars || 500)));
      if (step.captureMessages || step.expectMessageTextContains || step.expectJson || step.extractJson || step.extract_json) {
        record.messagesPath = await writeTextArtifact(ctx, `${scenario.id}-${step.id || "websocket"}-messages`, wsResult.messages.join("\n"));
      }
      const parsed = parseJsonItems(wsResult.messages);
      const matched = step.expectJson ? findJsonMatch(parsed, step.expectJson) : undefined;
      if (step.extractJson || step.extract_json) {
        applyJsonExtraction(record, parsed, step, ctx, matched);
      }
      if (wsResult.errors.length) throw new Error(`WebSocket probe errors: ${wsResult.errors.join("; ")}`);
      if (step.expectOpen !== false && !wsResult.opened) throw new Error("WebSocket did not open.");
      if (step.expectMessageTextContains && !wsResult.messages.some((msg) => msg.includes(step.expectMessageTextContains))) {
        throw new Error(`No WebSocket message contained: ${step.expectMessageTextContains}`);
      }
      if (step.expectMessageTextContains) {
        record.messageTextContainsMatched = String(step.expectMessageTextContains);
      }
      if (step.expectJson) {
        if (!matched) throw new Error(`No WebSocket JSON message matched expectations: ${JSON.stringify(redact(step.expectJson))}`);
        record.checkedJson = assertJson(matched, step.expectJson);
      }
    } else if (step.action === "sse") {
      const url = resolveUrl(ctx.baseUrl, step, ctx);
      const sseResult = await runSseProbe(page, url, step);
      record.url = redactString(url);
      record.opened = sseResult.opened;
      record.messageCount = sseResult.messages.length;
      record.messagesPreview = sseResult.messages.slice(0, Number(step.maxMessages || 20)).map((msg) => boundedText(msg, Number(step.maxMessageChars || 500)));
      if (step.captureMessages || step.expectMessageTextContains || step.expectJson || step.extractJson || step.extract_json) {
        record.messagesPath = await writeTextArtifact(ctx, `${scenario.id}-${step.id || "sse"}-messages`, sseResult.messages.join("\n"));
      }
      const parsed = parseJsonItems(sseResult.messages);
      const matched = step.expectJson ? findJsonMatch(parsed, step.expectJson) : undefined;
      if (step.extractJson || step.extract_json) {
        applyJsonExtraction(record, parsed, step, ctx, matched);
      }
      const allowTerminalError = step.allowErrorEventAfterMessage !== false;
      const nonTerminalErrors = sseResult.errors.filter((message) => !allowTerminalError || !sseResult.messages.length || !message.includes("EventSource error"));
      if (nonTerminalErrors.length) throw new Error(`SSE probe errors: ${nonTerminalErrors.join("; ")}`);
      if (step.expectOpen !== false && !sseResult.opened) throw new Error("SSE stream did not open.");
      if (step.expectMessageTextContains && !sseResult.messages.some((msg) => msg.includes(step.expectMessageTextContains))) {
        throw new Error(`No SSE message contained: ${step.expectMessageTextContains}`);
      }
      if (step.expectMessageTextContains) {
        record.messageTextContainsMatched = String(step.expectMessageTextContains);
      }
      if (step.expectJson) {
        if (!matched) throw new Error(`No SSE JSON message matched expectations: ${JSON.stringify(redact(step.expectJson))}`);
        record.checkedJson = assertJson(matched, step.expectJson);
      }
    } else if (step.action === "command") {
      if (ctx.actionJournal) {
        commandDispatch =
          await verifyCurrentCommandExecutionBinding(
            runtimeContract,
            step,
          );
      }
      const commandResult = await runCommand(
        step,
        ctx,
        commandDispatch,
      );
      record.exitCode = commandResult.exitCode;
      record.timedOut = !!commandResult.timedOut;
      if (commandResult.error) record.commandError = boundedText(commandResult.error, 500);
      const needsStdoutArtifact = step.expectStdoutJson || step.expect_stdout_json || step.expectStdoutJsonAny || step.expect_stdout_json_any || step.extractStdoutJson || step.extract_stdout_json || step.expectStdoutContains;
      if ((step.captureStdout !== false || needsStdoutArtifact) && commandResult.stdout) {
        record.stdoutPath = await writeTextArtifact(ctx, `${scenario.id}-${step.id || "command"}-stdout`, commandResult.stdout);
        record.stdoutPreview = boundedText(commandResult.stdout, Number(step.maxStdoutChars || 800));
      }
      if (step.captureStderr !== false && commandResult.stderr) {
        record.stderrPath = await writeTextArtifact(ctx, `${scenario.id}-${step.id || "command"}-stderr`, commandResult.stderr);
        record.stderrPreview = boundedText(commandResult.stderr, Number(step.maxStderrChars || 800));
      }
      const expectedExit = step.expectExitCode === undefined ? 0 : Number(step.expectExitCode);
      if (commandResult.timedOut) throw new Error(`Command timed out after ${step.timeoutMs || 30000}ms`);
      if (commandResult.exitCode !== expectedExit) throw new Error(`Expected exit code ${expectedExit}, got ${commandResult.exitCode}`);
      if (step.expectStdoutContains && !commandResult.stdout.includes(step.expectStdoutContains)) {
        throw new Error(`stdout did not contain expected text: ${step.expectStdoutContains}`);
      }
      if (step.expectStdoutContains) {
        record.stdoutContainsMatched = String(step.expectStdoutContains);
      }
      if (step.expectStderrContains && !commandResult.stderr.includes(step.expectStderrContains)) {
        throw new Error(`stderr did not contain expected text: ${step.expectStderrContains}`);
      }
      if (step.expectStderrContains) {
        record.stderrContainsMatched = String(step.expectStderrContains);
      }
      inspectStdoutJson(record, commandResult.stdout, step, ctx);
    } else {
      throw new Error(`Unsupported action: ${step.action}`);
    }
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    if (rawStep.action === "cleanupApi" && rawStep.skipIfMissingVars !== false && /^Missing runtime variable/.test(message)) {
      record.status = "skipped";
      record.skipped = true;
      record.skipReason = boundedText(message, 1200);
    } else {
      record.status = "failed";
      record.error = boundedText(message, 1200);
    }
    if (error && error.hitTest) record.hitTest = redact(error.hitTest);
    if (record.status === "failed" && page && !["api", "cleanupApi", "command"].includes(step.action)) {
      const file = path.join(ctx.screenshotDir, `${scenario.id}-${safeName(step.id || step.action)}-failed.png`);
      await page.screenshot({ path: file, fullPage: true }).then(() => {
        record.screenshot = file;
      }).catch(() => {});
    }
  }

  record.finishedAt = new Date().toISOString();
  if (ctx.actionJournal && dispatchToken) {
    await ctx.actionJournal.commit(dispatchToken, record.status);
  }
  return redact(record);
}

function skippedStepRecord(scenario, rawStep, reason) {
  const now = new Date().toISOString();
  return redact({
    scenarioId: scenario.id,
    stepId: rawStep.id || "",
    testIds: rawStep.testIds || rawStep.test_ids || [],
    requirementIds: rawStep.requirementIds || rawStep.requirement_ids || [],
    action: rawStep.action,
    title: rawStep.title || "",
    evidenceType: rawStep.evidenceType || rawStep.evidence_type || "",
    proves: rawStep.proves || "",
    startedAt: now,
    finishedAt: now,
    status: "skipped",
    skipped: true,
    skipReason: reason,
  });
}

function planNeedsBrowser(plan) {
  const browserlessActions = new Set(["command", "api", "cleanupApi", "pollApi"]);
  for (const scenario of plan.scenarios || []) {
    for (const step of scenario.steps || []) {
      if (step && !browserlessActions.has(step.action)) return true;
    }
  }
  return false;
}

function planNeedsApiRequest(plan) {
  const apiActions = new Set(["api", "cleanupApi", "pollApi"]);
  for (const scenario of plan.scenarios || []) {
    for (const step of scenario.steps || []) {
      if (step && apiActions.has(step.action)) return true;
    }
  }
  return false;
}

async function launchBrowser(chromium, plan) {
  const launchOptions = { ...(plan.launchOptions || {}), headless: plan.headless !== false };
  if (plan.channel) launchOptions.channel = plan.channel;
  try {
    return await chromium.launch(launchOptions);
  } catch (error) {
    if (!plan.channel && process.platform === "darwin") {
      return await chromium.launch({ ...launchOptions, channel: "chrome" });
    }
    throw error;
  }
}

async function loadPlaywright(planPath, plan) {
  try {
    return await import("playwright");
  } catch (firstError) {
    const errors = [firstError.message || String(firstError)];
    const cwd = process.cwd();
    const candidates = [
      plan.playwrightRequireFrom,
      process.env.PLAYWRIGHT_REQUIRE_FROM,
      cwd,
      path.join(cwd, "web"),
      path.join(cwd, "frontend"),
      path.join(cwd, "one_corpus_web"),
      path.join(cwd, "ops_web"),
      path.join(cwd, "agent_platform", "web"),
      path.dirname(planPath),
    ].filter(Boolean);

    for (const candidate of candidates) {
      const packageJson = path.join(String(candidate), "package.json");
      try {
        await fs.access(packageJson);
        const req = createRequire(packageJson);
        for (const packageName of ["playwright", "@playwright/test", "playwright-core"]) {
          try {
            return req(packageName);
          } catch (error) {
            errors.push(`${packageName} from ${candidate}: ${error.message || String(error)}`);
          }
        }
      } catch (_) {
        // 候选路径不像包根目录。
      }
    }

    throw new Error(errors.join("\n"));
  }
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    usage();
    return 0;
  }

  const planPath = argValue("--plan");
  const planAuditSummaryPath = argValue("--plan-audit-summary");
  const agentContextPath = argValue("--agent-context");
  const actionContractsPath = argValue("--action-contracts");
  const actionJournalPath = argValue("--action-journal");
  if (!planPath) {
    usage();
    return 2;
  }

  let planInput;
  let planAuditInput = null;
  let agentContextInput = null;
  let rawPlan;
  let plan;
  try {
    planInput = await readStableJsonInput(planPath, "plan");
    rawPlan = planInput.value;
    if (planAuditSummaryPath) {
      planAuditInput = await readStableJsonInput(
        planAuditSummaryPath,
        "plan audit",
      );
    }
    if (agentContextPath) {
      agentContextInput = await readStableJsonInput(
        agentContextPath,
        "agent context",
      );
    }
    validatePlanReferenceBoundary(rawPlan);
    plan = resolveEnvRefs(rawPlan);
  } catch (error) {
    console.error(`Could not read or resolve plan: ${planPath}`);
    console.error(error.message || String(error));
    return 2;
  }
  if (plan.schemaVersion !== 2) {
    console.error(`Unsupported plan.schemaVersion: ${JSON.stringify(plan.schemaVersion)}; expected 2.`);
    return 2;
  }
  try {
    await validateCommandPlanBinding(
      rawPlan,
      planInput,
      planAuditInput,
    );
  } catch (error) {
    console.error("Command plan validation binding failed.");
    console.error(error.message || String(error));
    return 2;
  }

  const needsBrowser = planNeedsBrowser(rawPlan);
  const needsApiRequest = planNeedsApiRequest(rawPlan);
  let chromium;
  let request;
  if (needsBrowser || needsApiRequest) {
    try {
      ({ chromium, request } = await loadPlaywright(planInput.path, plan));
    } catch (error) {
      console.error("Could not import Playwright. Install project dependencies or run from a workspace that has playwright available.");
      console.error(error.message || String(error));
      return 2;
    }
  }

  const artifactDir = path.resolve(
    plan.artifactDir || path.dirname(planInput.path),
  );
  const screenshotDir = path.join(artifactDir, "screenshots");
  const evidenceDir = path.join(artifactDir, "evidence");
  await ensureDir(screenshotDir);
  await ensureDir(evidenceDir);
  if (!!actionContractsPath !== !!actionJournalPath) {
    console.error("--action-contracts and --action-journal must be provided together.");
    return 2;
  }
  let actionJournal = null;
  if (actionContractsPath && actionJournalPath) {
    try {
      actionJournal = await DurableActionJournal.open(
        path.resolve(actionJournalPath),
        path.resolve(actionContractsPath),
        planInput,
        planAuditInput,
        agentContextInput,
      );
    } catch (error) {
      console.error("Action dispatch recovery boundary failed closed.");
      console.error(error.message || String(error));
      return 3;
    }
  }

  const startedAt = new Date();
  const runtimeVars = buildRuntimeVars(plan, startedAt);
  const result = {
    schemaVersion: 2,
    planPath: planInput.path,
    artifactDir,
    baseUrl: plan.baseUrl,
    startedAt: startedAt.toISOString(),
    run: {
      qaRunId: runtimeVars.qa_run_id,
      qaMarker: runtimeVars.qa_marker,
      runtimeVarNames: Object.keys(runtimeVars).sort(),
    },
    scenarios: [],
    console: [],
    failedResponses: [],
    requests: [],
    requestFailures: [],
    webSockets: [],
  };

  let browser = null;
  let context = null;
  let page = null;
  if (needsBrowser) {
    browser = await launchBrowser(chromium, plan);
    const contextOptions = {
      ...(plan.contextOptions || {}),
      viewport: plan.viewport || (plan.contextOptions || {}).viewport || { width: 1440, height: 980 },
    };
    if (plan.storageState) contextOptions.storageState = plan.storageState;
    if (plan.extraHTTPHeaders) contextOptions.extraHTTPHeaders = plan.extraHTTPHeaders;
    context = await browser.newContext(contextOptions);
    page = await context.newPage();

    page.on("console", (msg) => {
      if (["error", "warning"].includes(msg.type())) {
        result.console.push(redact({ type: msg.type(), text: msg.text(), url: page.url(), time: new Date().toISOString() }));
      }
    });
    page.on("response", (response) => {
      if (response.status() >= 400) {
        result.failedResponses.push(redact({ status: response.status(), url: response.url(), time: new Date().toISOString() }));
      }
    });
    page.on("request", (request) => {
      result.requests.push(redact({
        method: request.method(),
        url: request.url(),
        resourceType: request.resourceType(),
        time: new Date().toISOString(),
      }));
    });
    page.on("requestfailed", (request) => {
      result.requestFailures.push(redact({
        method: request.method(),
        url: request.url(),
        failure: request.failure()?.errorText || "",
        time: new Date().toISOString(),
      }));
    });
    if (plan.captureWebSockets !== false) {
      page.on("websocket", (ws) => {
        const entry = redact({ url: ws.url(), openedAt: new Date().toISOString(), framesSent: [], framesReceived: [] });
        result.webSockets.push(entry);
        ws.on("framesent", (event) => entry.framesSent.push({ time: new Date().toISOString(), payload: boundedText(event.payload, 500) }));
        ws.on("framereceived", (event) => entry.framesReceived.push({ time: new Date().toISOString(), payload: boundedText(event.payload, 500) }));
        ws.on("close", () => {
          entry.closedAt = new Date().toISOString();
        });
      });
    }
  } else if (needsApiRequest) {
    const requestContextOptions = {};
    if (plan.baseUrl) requestContextOptions.baseURL = plan.baseUrl;
    if (plan.storageState) requestContextOptions.storageState = plan.storageState;
    if (plan.extraHTTPHeaders) requestContextOptions.extraHTTPHeaders = plan.extraHTTPHeaders;
    context = { request: await request.newContext(requestContextOptions) };
  }

  const ctx = {
    baseUrl: plan.baseUrl || "",
    rawBaseUrl: rawPlan.baseUrl,
    defaultHeaders: plan.defaultHeaders || {},
    rawDefaultHeaders: rawPlan.defaultHeaders || {},
    extraHTTPHeaders: plan.extraHTTPHeaders || {},
    rawExtraHTTPHeaders: rawPlan.extraHTTPHeaders || {},
    screenshotDir,
    evidenceDir,
    maxArtifactChars: Number(plan.maxArtifactChars || 10000),
    result,
    vars: runtimeVars,
    lastStepStartedAtByScenario: Object.create(null),
    actionJournal,
  };

  for (const scenario of rawPlan.scenarios || []) {
    const scenarioResult = { id: scenario.id, title: scenario.title || scenario.id, steps: [] };
    let stopNormalSteps = false;
    for (const step of scenario.steps || []) {
      const alwaysRun = step.alwaysRun === true || step.action === "cleanupApi";
      if (stopNormalSteps && !alwaysRun) {
        if (actionJournal) await actionJournal.skipped(scenario, step);
        scenarioResult.steps.push(skippedStepRecord(scenario, step, "Skipped because an earlier scenario step failed and continueOnFailure was not enabled."));
        continue;
      }
      const stepResult = await runStep(page, context, scenario, step, ctx);
      scenarioResult.steps.push(stepResult);
      if (stepResult.status === "failed" && step.continueOnFailure !== true && scenario.continueOnFailure !== true) {
        stopNormalSteps = true;
      }
    }
    scenarioResult.status = scenarioResult.steps.some((s) => s.status === "failed") ? "failed" : "passed";
    result.scenarios.push(scenarioResult);
  }

  result.finishedAt = new Date().toISOString();
  result.status = result.scenarios.some((s) => s.status === "failed") ||
    result.failedResponses.length ||
    result.requestFailures.length ||
    result.console.some((m) => m.type === "error")
    ? "attention"
    : "passed";
  if (browser) {
    await browser.close();
  } else if (context?.request) {
    await context.request.dispose();
  }
  if (actionJournal) await actionJournal.close();

  const resultPath = path.join(artifactDir, "results.json");
  await fs.writeFile(resultPath, JSON.stringify(redact(result), null, 2), "utf-8");
  console.log(resultPath);
  return 0;
}

main().then((code) => process.exit(code)).catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
