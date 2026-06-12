#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

function usage() {
  console.log("Usage: playwright_probe.mjs --plan <test-plan.json>");
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  return idx >= 0 ? process.argv[idx + 1] : undefined;
}

function safeName(value) {
  return String(value || "screenshot").replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "") || "screenshot";
}

function resolveUrl(baseUrl, step) {
  if (step.url) return step.url;
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const rel = String(step.path || "/").startsWith("/") ? step.path : `/${step.path}`;
  return `${base}${rel}`;
}

function readPath(obj, dottedPath) {
  return String(dottedPath || "").split(".").filter(Boolean).reduce((acc, key) => {
    if (acc === undefined || acc === null) return undefined;
    return acc[key];
  }, obj);
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function runStep(page, request, scenario, step, ctx) {
  const startedAt = new Date().toISOString();
  const record = {
    scenarioId: scenario.id,
    stepId: step.id || "",
    requirementIds: step.requirementIds || step.requirement_ids || [],
    action: step.action,
    title: step.title || "",
    evidenceType: step.evidenceType || "",
    proves: step.proves || "",
    startedAt,
    status: "passed",
  };
  try {
    if (step.action === "goto") {
      const url = resolveUrl(ctx.baseUrl, step);
      await page.goto(url, { waitUntil: "networkidle", timeout: step.timeoutMs || 30000 });
      record.url = page.url();
    } else if (step.action === "clickText") {
      await page.getByText(step.text, { exact: !!step.exact }).click({ timeout: step.timeoutMs || 10000 });
    } else if (step.action === "clickRole") {
      await page.getByRole(step.role, { name: step.name, exact: !!step.exact }).click({ timeout: step.timeoutMs || 10000 });
    } else if (step.action === "fillLabel") {
      await page.getByLabel(step.label, { exact: !!step.exact }).fill(String(step.value ?? ""), { timeout: step.timeoutMs || 10000 });
    } else if (step.action === "fillPlaceholder") {
      await page.getByPlaceholder(step.placeholder, { exact: !!step.exact }).fill(String(step.value ?? ""), { timeout: step.timeoutMs || 10000 });
    } else if (step.action === "press") {
      await page.keyboard.press(step.key);
    } else if (step.action === "wait") {
      await page.waitForTimeout(step.ms || 500);
    } else if (step.action === "expectText") {
      await page.getByText(step.text, { exact: !!step.exact }).waitFor({ state: "visible", timeout: step.timeoutMs || 10000 });
    } else if (step.action === "expectUrlContains") {
      const current = page.url();
      if (!current.includes(step.text)) throw new Error(`URL does not contain ${step.text}: ${current}`);
      record.url = current;
    } else if (step.action === "screenshot") {
      const file = path.join(ctx.screenshotDir, `${scenario.id}-${safeName(step.name)}.png`);
      await page.screenshot({ path: file, fullPage: step.fullPage !== false });
      record.screenshot = file;
    } else if (step.action === "api") {
      const url = resolveUrl(ctx.baseUrl, step);
      const response = await request.get(url, { timeout: step.timeoutMs || 15000 });
      record.url = url;
      record.statusCode = response.status();
      if (step.expectStatus && response.status() !== step.expectStatus) {
        throw new Error(`Expected status ${step.expectStatus}, got ${response.status()}`);
      }
      if (step.expectResponseTextContains || step.captureBody) {
        const text = await response.text();
        if (step.captureBody) {
          const maxBodyChars = Number(step.maxBodyChars || 500);
          record.bodyPreview = text.slice(0, Math.max(0, maxBodyChars));
        }
        if (step.expectResponseTextContains && !text.includes(step.expectResponseTextContains)) {
          throw new Error(`Response text did not contain expected text: ${step.expectResponseTextContains}`);
        }
      }
      if (step.expectJson) {
        const body = await response.json();
        record.checkedJson = {};
        for (const [jsonPath, expectedValue] of Object.entries(step.expectJson)) {
          const actualValue = readPath(body, jsonPath);
          record.checkedJson[jsonPath] = actualValue;
          if (JSON.stringify(actualValue) !== JSON.stringify(expectedValue)) {
            throw new Error(`JSON path ${jsonPath} expected ${JSON.stringify(expectedValue)}, got ${JSON.stringify(actualValue)}`);
          }
        }
      }
    } else {
      throw new Error(`Unsupported action: ${step.action}`);
    }
  } catch (error) {
    record.status = "failed";
    record.error = error && error.message ? error.message : String(error);
    const file = path.join(ctx.screenshotDir, `${scenario.id}-${safeName(step.action)}-failed.png`);
    await page.screenshot({ path: file, fullPage: true }).catch(() => {});
    record.screenshot = file;
  }
  record.finishedAt = new Date().toISOString();
  return record;
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    usage();
    return 0;
  }

  const planPath = argValue("--plan");
  if (!planPath) {
    usage();
    return 2;
  }

  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch (error) {
    console.error("Could not import Playwright. Install project dependencies or run from a workspace that has playwright available.");
    console.error(error.message || String(error));
    return 2;
  }

  const plan = JSON.parse(await fs.readFile(planPath, "utf-8"));
  const artifactDir = path.resolve(plan.artifactDir || path.dirname(planPath));
  const screenshotDir = path.join(artifactDir, "screenshots");
  await ensureDir(screenshotDir);

  const result = {
    planPath: path.resolve(planPath),
    artifactDir,
    baseUrl: plan.baseUrl,
    startedAt: new Date().toISOString(),
    scenarios: [],
    console: [],
    failedResponses: [],
  };

  const browser = await chromium.launch({ headless: plan.headless !== false });
  const context = await browser.newContext({ viewport: plan.viewport || { width: 1440, height: 980 } });
  const page = await context.newPage();

  page.on("console", (msg) => {
    if (["error", "warning"].includes(msg.type())) {
      result.console.push({ type: msg.type(), text: msg.text(), url: page.url(), time: new Date().toISOString() });
    }
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      result.failedResponses.push({ status: response.status(), url: response.url(), time: new Date().toISOString() });
    }
  });

  const ctx = { baseUrl: plan.baseUrl || "", screenshotDir };
  for (const scenario of plan.scenarios || []) {
    const scenarioResult = { id: scenario.id, title: scenario.title || scenario.id, steps: [] };
    for (const step of scenario.steps || []) {
      const stepResult = await runStep(page, context.request, scenario, step, ctx);
      scenarioResult.steps.push(stepResult);
      if (stepResult.status === "failed" && step.continueOnFailure !== true) break;
    }
    scenarioResult.status = scenarioResult.steps.some((s) => s.status === "failed") ? "failed" : "passed";
    result.scenarios.push(scenarioResult);
  }

  result.finishedAt = new Date().toISOString();
  result.status = result.scenarios.some((s) => s.status === "failed") || result.failedResponses.length || result.console.some((m) => m.type === "error") ? "attention" : "passed";
  await browser.close();

  const resultPath = path.join(artifactDir, "results.json");
  await fs.writeFile(resultPath, JSON.stringify(result, null, 2));
  console.log(resultPath);
  return 0;
}

main().then((code) => process.exit(code)).catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
