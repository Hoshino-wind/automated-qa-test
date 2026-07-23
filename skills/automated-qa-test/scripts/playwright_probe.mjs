#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";

function usage() {
  console.log("Usage: playwright_probe.mjs --plan <test-plan.json> [--plan-audit-summary <plan-audit-summary.json>]");
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

function redactString(value) {
  return String(value)
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

async function validateCommandPlanBinding(plan, planPath, auditPath) {
  if (!planNeedsCommand(plan)) return;
  if (!auditPath) {
    throw new Error("Command plans require --plan-audit-summary; refusing to execute an unvalidated local command.");
  }
  const audit = JSON.parse(await fs.readFile(auditPath, "utf-8"));
  const expectedPlan = path.resolve(planPath);
  const boundPlan = audit.plan ? path.resolve(String(audit.plan)) : "";
  const expectedHash = await sha256File(planPath);
  const boundHash = audit.artifact_hashes?.plan_sha256;
  if (audit.passed !== true) throw new Error("Command plan audit is not passed.");
  if (boundPlan !== expectedPlan) throw new Error("Command plan audit path does not match --plan.");
  if (!boundHash || boundHash !== expectedHash) throw new Error("Command plan changed after validation; SHA-256 binding mismatch.");
}

function resolveRuntimeRefs(value, ctx) {
  if (Array.isArray(value)) return value.map((item) => resolveRuntimeRefs(item, ctx));
  if (isObject(value)) {
    const templateValue = Object.prototype.hasOwnProperty.call(value, "template") ? value.template : value.$template;
    if (typeof templateValue === "string") {
      const rendered = resolveTemplateString(templateValue, ctx, value.encodeVars === true);
      if (value.json === true) return JSON.parse(rendered);
      return rendered;
    }
    const varName = value.var || value.$var;
    if (typeof varName === "string" && varName.trim()) {
      if (!Object.prototype.hasOwnProperty.call(ctx.vars || {}, varName)) {
        throw new Error(`Missing runtime variable: ${varName}`);
      }
      const raw = ctx.vars[varName];
      const resolved = `${value.prefix || ""}${raw}${value.suffix || ""}`;
      if (value.json === true) return JSON.parse(resolved);
      return resolved;
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = resolveRuntimeRefs(item, ctx);
    }
    return out;
  }
  return value;
}

function resolveEnvRefs(value) {
  if (Array.isArray(value)) return value.map((item) => resolveEnvRefs(item));
  if (isObject(value)) {
    const envName = value.env || value.$env;
    if (typeof envName === "string" && envName.trim()) {
      const raw = process.env[envName];
      if (raw === undefined) throw new Error(`Missing required environment variable: ${envName}`);
      const resolved = `${value.prefix || ""}${raw}${value.suffix || ""}`;
      if (value.json === true) return JSON.parse(resolved);
      return resolved;
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = resolveEnvRefs(item);
    }
    return out;
  }
  return value;
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

async function runCommand(step, ctx) {
  const timeoutMs = Number(step.timeoutMs || 30000);
  const commandValue = step.command || step.cmd;
  if (!commandValue) throw new Error("command step requires command or cmd.");

  const useShell = step.shell === true || typeof commandValue === "string";
  const command = Array.isArray(commandValue) ? commandValue[0] : String(commandValue);
  const args = Array.isArray(commandValue) ? commandValue.slice(1).map(String) : [];
  const cwd = step.cwd ? path.resolve(String(step.cwd)) : process.cwd();
  const env = { ...process.env, ...(step.env || {}) };

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
    step = resolveRuntimeRefs(rawStep, ctx);
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
      const commandResult = await runCommand(step, ctx);
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
  for (const scenario of plan.scenarios || []) {
    for (const step of scenario.steps || []) {
      if (step && step.action !== "command") return true;
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
  if (!planPath) {
    usage();
    return 2;
  }

  let plan;
  try {
    plan = resolveEnvRefs(JSON.parse(await fs.readFile(planPath, "utf-8")));
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
    await validateCommandPlanBinding(plan, planPath, planAuditSummaryPath);
  } catch (error) {
    console.error("Command plan validation binding failed.");
    console.error(error.message || String(error));
    return 2;
  }

  const needsBrowser = planNeedsBrowser(plan);
  let chromium;
  if (needsBrowser) {
    try {
      ({ chromium } = await loadPlaywright(path.resolve(planPath), plan));
    } catch (error) {
      console.error("Could not import Playwright. Install project dependencies or run from a workspace that has playwright available.");
      console.error(error.message || String(error));
      return 2;
    }
  }

  const artifactDir = path.resolve(plan.artifactDir || path.dirname(planPath));
  const screenshotDir = path.join(artifactDir, "screenshots");
  const evidenceDir = path.join(artifactDir, "evidence");
  await ensureDir(screenshotDir);
  await ensureDir(evidenceDir);

  const startedAt = new Date();
  const runtimeVars = buildRuntimeVars(plan, startedAt);
  const result = {
    schemaVersion: 2,
    planPath: path.resolve(planPath),
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
  }

  const ctx = {
    baseUrl: plan.baseUrl || "",
    defaultHeaders: plan.defaultHeaders || {},
    screenshotDir,
    evidenceDir,
    maxArtifactChars: Number(plan.maxArtifactChars || 10000),
    result,
    vars: runtimeVars,
    lastStepStartedAtByScenario: Object.create(null),
  };

  for (const scenario of plan.scenarios || []) {
    const scenarioResult = { id: scenario.id, title: scenario.title || scenario.id, steps: [] };
    let stopNormalSteps = false;
    for (const step of scenario.steps || []) {
      const alwaysRun = step.alwaysRun === true || step.action === "cleanupApi";
      if (stopNormalSteps && !alwaysRun) {
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
  if (browser) await browser.close();

  const resultPath = path.join(artifactDir, "results.json");
  await fs.writeFile(resultPath, JSON.stringify(redact(result), null, 2), "utf-8");
  console.log(resultPath);
  return 0;
}

main().then((code) => process.exit(code)).catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
