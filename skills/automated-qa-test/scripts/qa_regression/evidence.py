"""证据完整性、报告、浏览器与实时链路回归夹具。"""

import base64
import hashlib
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from .support import (
    VALID_PNG_1X1,
    assert_true,
    load_json,
    run_cmd,
    write_json,
    write_synthetic_passing_audit_summary,
)


def run_browser_hit_test_fixture(script_dir: Path, tmp_path: Path) -> None:
    browser_dir = tmp_path / "browser-hit-test"
    browser_dir.mkdir(parents=True, exist_ok=True)
    html_path = browser_dir / "page.html"
    html_path.write_text(
        """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Hit Test Fixture</title>
    <style>
      body { font-family: sans-serif; padding: 40px; }
      .stack { position: relative; width: 240px; height: 80px; margin-top: 24px; }
      .blocked-button { position: absolute; left: 0; top: 0; width: 200px; height: 48px; }
      .blocking-overlay { position: absolute; left: 0; top: 0; width: 200px; height: 48px; background: rgba(200, 0, 0, 0.3); z-index: 2; }
    </style>
  </head>
  <body>
    <button id="ok">Save</button>
    <div class="stack">
      <button id="blocked" class="blocked-button">Delete</button>
      <div class="blocking-overlay" data-onboarding="blocking-overlay">Blocking overlay</div>
    </div>
  </body>
</html>
""",
        encoding="utf-8",
    )
    write_json(
        browser_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {"id": "R-open", "source": "fixture", "text": "Fixture page opens.", "test_ids": ["T-open"], "status": "Untested"},
                {"id": "R-save", "source": "fixture", "text": "Save button is clickable.", "test_ids": ["T-save"], "status": "Untested"},
                {"id": "R-delete", "source": "fixture", "text": "Delete button is clickable.", "test_ids": ["T-delete"], "status": "Untested"},
                {"id": "R-skipped", "source": "fixture", "text": "A planned assertion after a failure must not silently pass.", "test_ids": ["T-skipped"], "status": "Untested"},
            ],
            "tests": [
                {"id": "T-open", "requirement_ids": ["R-open"], "type": "ui", "expected": "Fixture opens.", "status": "Untested"},
                {"id": "T-save", "requirement_ids": ["R-save"], "type": "interaction", "expected": "Save receives pointer events.", "status": "Untested"},
                {"id": "T-delete", "requirement_ids": ["R-delete"], "type": "interaction", "expected": "Delete receives pointer events.", "status": "Untested"},
                {"id": "T-skipped", "requirement_ids": ["R-skipped"], "type": "ui", "expected": "Both planned assertions execute before a pass is possible.", "status": "Untested"},
            ],
        },
    )
    write_json(
        browser_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "artifactDir": str(browser_dir),
            "headless": True,
            "scenarios": [
                {
                    "id": "hit-test",
                    "continueOnFailure": True,
                    "steps": [
                        {
                            "action": "goto",
                            "id": "open",
                            "url": html_path.resolve().as_uri(),
                            "testIds": ["T-open"],
                            "requirementIds": ["R-open"],
                            "evidenceType": "navigation",
                            "proves": "Fixture page opens.",
                        },
                        {
                            "action": "expectClickable",
                            "id": "save-clickable",
                            "role": "button",
                            "name": "Save",
                            "testIds": ["T-save"],
                            "requirementIds": ["R-save"],
                            "evidenceType": "ui_interaction",
                            "proves": "Save button receives pointer events.",
                        },
                        {
                            "action": "expectClickable",
                            "id": "delete-clickable",
                            "role": "button",
                            "name": "Delete",
                            "testIds": ["T-delete"],
                            "requirementIds": ["R-delete"],
                            "evidenceType": "ui_interaction",
                            "proves": "Delete button receives pointer events.",
                        },
                    ],
                },
                {
                    "id": "skipped-after-failure",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "skipped-open",
                            "url": html_path.resolve().as_uri(),
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "navigation",
                            "proves": "The skipped-step scenario opens the fixture page independently.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-setup-visible",
                            "text": "Save",
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "ui_assertion",
                            "proves": "The fixture page was still visible before the later failure.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-trigger-failure",
                            "text": "Text that is intentionally absent",
                            "testIds": ["T-delete"],
                            "requirementIds": ["R-delete"],
                            "evidenceType": "ui_assertion",
                            "proves": "An intentional failure stops normal follow-up steps.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-critical-assertion",
                            "text": "Save",
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "ui_assertion",
                            "proves": "This critical planned assertion must be recorded as skipped, not silently omitted.",
                        },
                    ],
                }
            ],
        },
    )
    run_cmd(["node", str(script_dir / "playwright_probe.mjs"), "--plan", str(browser_dir / "test-plan.json")], cwd=browser_dir)
    results = load_json(browser_dir / "results.json")
    failed_step = results["scenarios"][0]["steps"][2]
    skipped_scenario = next(scenario for scenario in results.get("scenarios", []) if scenario.get("id") == "skipped-after-failure")
    skipped_step = next(step for step in skipped_scenario.get("steps", []) if step.get("stepId") == "skipped-critical-assertion")
    assert_true(results.get("status") == "attention", "browser hit-test fixture should produce attention status.")
    assert_true(failed_step.get("status") == "failed", "blocked Delete button should fail expectClickable.")
    assert_true((failed_step.get("hitTest") or {}).get("blocker", {}).get("dataOnboarding") == "blocking-overlay", "blocked hit-test should preserve blocker details.")
    assert_true(skipped_step.get("status") == "skipped", "runner should record planned steps skipped after an earlier failure.")
    assert_true(skipped_step.get("testIds") == ["T-skipped"], "skipped step should preserve test lineage.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--out",
            str(browser_dir / "evidence-ledger.json"),
        ],
        cwd=browser_dir,
    )
    browser_ledger = load_json(browser_dir / "evidence-ledger.json")
    skipped_test = next(test for test in browser_ledger.get("tests", []) if test.get("id") == "T-skipped")
    skipped_requirement = next(req for req in browser_ledger.get("requirements", []) if req.get("id") == "R-skipped")
    assert_true(skipped_test.get("status") == "Inconclusive", "a test with skipped planned assertions must not be marked Passed.")
    assert_true(skipped_requirement.get("status") == "Inconclusive", "a requirement with skipped planned assertions must not be marked Passed.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--summary",
            str(browser_dir / "audit-summary.json"),
        ],
        cwd=browser_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--out",
            str(browser_dir / "defects.json"),
        ],
        cwd=browser_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(browser_dir / "test-plan.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(browser_dir / "audit-summary.json"),
            "--defects",
            str(browser_dir / "defects.json"),
            "--out",
            str(browser_dir / "report.md"),
        ],
        cwd=browser_dir,
    )
    ledger = load_json(browser_dir / "evidence-ledger.json")
    defects = load_json(browser_dir / "defects.json")
    report = (browser_dir / "report.md").read_text(encoding="utf-8")
    failed_evidence = next(item for item in ledger.get("evidence", []) if item.get("step_id") == "delete-clickable")
    assert_true(failed_evidence.get("hit_test", {}).get("blocker", {}).get("dataOnboarding") == "blocking-overlay", "ledger should retain hit-test blocker details.")
    assert_true(defects.get("summary", {}).get("finding_count") == 1, "blocked clickability should generate one defect.")
    assert_true("Hit test:" in report and "blocking-overlay" in report, "report should render hit-test blocker details.")


def run_request_absence_fixture(script_dir: Path, tmp_path: Path) -> None:
    request_dir = tmp_path / "request-absence"
    request_dir.mkdir(parents=True, exist_ok=True)

    class RequestAbsenceHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status: int, value: dict[str, Any]) -> None:
            self.send_bytes(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json")

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path != "/settings":
                self.send_json(404, {"error": "not_found"})
                return
            body = b"""<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Request absence fixture</title></head>
  <body>
    <main>
      <button type="button" id="cancel" onclick="window.cancelClicks = (window.cancelClicks || 0) + 1">Cancel</button>
      <button type="button" id="save" onclick="fetch('/api/v1/settings', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({source: 'save'})}).then(r => r.json()).then(() => { window.saved = true; })">Save</button>
    </main>
  </body>
</html>
"""
            self.send_bytes(200, body, "text/html; charset=utf-8")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            if length:
                self.rfile.read(length)
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/v1/settings":
                self.send_json(200, {"ok": True})
            else:
                self.send_json(404, {"error": "not_found"})

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadedHTTPServer(("127.0.0.1", 0), RequestAbsenceHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        write_json(
            request_dir / "test-matrix.json",
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R-cancel-no-request",
                        "source": "fixture",
                        "text": "Cancel must not call POST /api/v1/settings.",
                        "test_ids": ["T-cancel-no-request"],
                        "status": "Untested",
                    },
                    {
                        "id": "R-save-negative-control",
                        "source": "fixture",
                        "text": "Save is a negative-control path that does call POST /api/v1/settings.",
                        "test_ids": ["T-save-negative-control"],
                        "status": "Untested",
                    },
                ],
                "tests": [
                    {
                        "id": "T-cancel-no-request",
                        "requirement_ids": ["R-cancel-no-request"],
                        "type": "runtime",
                        "expected": "No POST /api/v1/settings is observed after clicking Cancel.",
                        "status": "Untested",
                    },
                    {
                        "id": "T-save-negative-control",
                        "requirement_ids": ["R-save-negative-control"],
                        "type": "runtime",
                        "expected": "The forbidden-request assertion fails when Save sends POST /api/v1/settings.",
                        "status": "Untested",
                    },
                ],
            },
        )
        write_json(
            request_dir / "test-plan.json",
            {
                "schemaVersion": 2,
                "baseUrl": base_url,
                "artifactDir": str(request_dir),
                "headless": True,
                "scenarios": [
                    {
                        "id": "no-request-pass",
                        "steps": [
                            {
                                "action": "goto",
                                "id": "pass-open",
                                "path": "/settings",
                                "testIds": ["T-cancel-no-request"],
                                "requirementIds": ["R-cancel-no-request"],
                                "evidenceType": "navigation",
                                "proves": "The settings page is open before checking Cancel.",
                            },
                            {
                                "action": "click",
                                "id": "pass-cancel",
                                "role": "button",
                                "name": "Cancel",
                                "testIds": ["T-cancel-no-request"],
                                "requirementIds": ["R-cancel-no-request"],
                                "evidenceType": "ui_interaction",
                                "proves": "Cancel is clicked before checking for forbidden requests.",
                            },
                            {
                                "action": "expectNoRequest",
                                "id": "pass-no-request",
                                "method": "POST",
                                "path": "/api/v1/settings",
                                "waitMs": 300,
                                "testIds": ["T-cancel-no-request"],
                                "requirementIds": ["R-cancel-no-request"],
                                "evidenceType": "forbidden request absence",
                                "proves": "Cancel did not call POST /api/v1/settings.",
                            },
                        ],
                    },
                    {
                        "id": "no-request-fail",
                        "steps": [
                            {
                                "action": "goto",
                                "id": "fail-open",
                                "path": "/settings",
                                "testIds": ["T-save-negative-control"],
                                "requirementIds": ["R-save-negative-control"],
                                "evidenceType": "navigation",
                                "proves": "The settings page is open before checking Save.",
                            },
                            {
                                "action": "click",
                                "id": "fail-save",
                                "role": "button",
                                "name": "Save",
                                "testIds": ["T-save-negative-control"],
                                "requirementIds": ["R-save-negative-control"],
                                "evidenceType": "ui_interaction",
                                "proves": "Save is clicked to trigger the negative-control request.",
                            },
                            {
                                "action": "expectNoRequest",
                                "id": "fail-no-request",
                                "method": "POST",
                                "path": "/api/v1/settings",
                                "waitMs": 300,
                                "testIds": ["T-save-negative-control"],
                                "requirementIds": ["R-save-negative-control"],
                                "evidenceType": "forbidden request absence",
                                "proves": "This negative-control assertion should fail because Save calls POST /api/v1/settings.",
                            },
                        ],
                    },
                ],
            },
        )
        run_cmd(["node", str(script_dir / "playwright_probe.mjs"), "--plan", str(request_dir / "test-plan.json")], cwd=request_dir)
        results = load_json(request_dir / "results.json")
        pass_scenario = next(scenario for scenario in results.get("scenarios", []) if scenario.get("id") == "no-request-pass")
        fail_scenario = next(scenario for scenario in results.get("scenarios", []) if scenario.get("id") == "no-request-fail")
        pass_step = next(step for step in pass_scenario.get("steps", []) if step.get("stepId") == "pass-no-request")
        fail_step = next(step for step in fail_scenario.get("steps", []) if step.get("stepId") == "fail-no-request")
        matching_requests = fail_step.get("matchingRequests") or []
        observed_posts = [
            request
            for request in results.get("requests", [])
            if request.get("method") == "POST" and urllib.parse.urlparse(str(request.get("url") or "")).path == "/api/v1/settings"
        ]
        assert_true(results.get("status") == "attention", "negative-control forbidden request should produce attention status.")
        assert_true(pass_step.get("status") == "passed" and pass_step.get("checkedNoRequest") == 0, "Cancel path should pass expectNoRequest.")
        assert_true(pass_step.get("checkedRequestMethod") == "POST", "pass evidence should record the checked request method.")
        assert_true(pass_step.get("checkedRequestTarget") == "/api/v1/settings", "pass evidence should record the checked request target.")
        assert_true(pass_step.get("matchingRequests") in (None, []), "Cancel path should not preserve matching forbidden requests.")
        assert_true(fail_step.get("status") == "failed", "Save negative-control path should fail expectNoRequest.")
        assert_true("Forbidden request observed" in str(fail_step.get("error") or ""), "failed expectNoRequest should explain the forbidden request count.")
        assert_true(matching_requests and matching_requests[0].get("method") == "POST", "failed expectNoRequest should retain matching request evidence.")
        assert_true(observed_posts, "runner should capture POST /api/v1/settings in the run-level request log.")
        run_cmd(
            [
                sys.executable,
                str(script_dir / "ledger_from_probe.py"),
                "--matrix",
                str(request_dir / "test-matrix.json"),
                "--results",
                str(request_dir / "results.json"),
                "--out",
                str(request_dir / "evidence-ledger.json"),
            ],
            cwd=request_dir,
        )
        ledger = load_json(request_dir / "evidence-ledger.json")
        pass_evidence = next(item for item in ledger.get("evidence", []) if item.get("step_id") == "pass-no-request")
        fail_evidence = next(item for item in ledger.get("evidence", []) if item.get("step_id") == "fail-no-request")
        assert_true(pass_evidence.get("checked_no_request") == 0, "ledger should preserve the passed no-request assertion.")
        assert_true(pass_evidence.get("checked_request_target") == "/api/v1/settings", "ledger should preserve the no-request target.")
        assert_true(fail_evidence.get("matching_requests"), "ledger should preserve matching forbidden request evidence for failures.")
    finally:
        server.shutdown()
        server.server_close()


def run_probe_redaction_fixture(script_dir: Path, tmp_path: Path) -> None:
    redaction_dir = tmp_path / "probe-redaction"
    redaction_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        redaction_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-redact",
                    "source": "fixture",
                    "text": "Runner command evidence must redact secret-like stdout and stderr values.",
                    "test_ids": ["T-redact"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-redact",
                    "requirement_ids": ["R-redact"],
                    "type": "command",
                    "expected": "Secret-like command output is redacted before persistence.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        redaction_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(redaction_dir),
            "headless": True,
            "scenarios": [
                {
                    "id": "redaction",
                    "steps": [
                        {
                            "action": "command",
                            "id": "T-redact-command",
                            "testIds": ["T-redact"],
                            "requirementIds": ["R-redact"],
                            "command": [
                                "python3",
                                "-c",
                                "import os,sys; label='pass'+'word'; one=os.environ['QA_REDACT_ONE']; two=os.environ['QA_REDACT_TWO']; three=os.environ['QA_REDACT_THREE']; print(label+'='+one); print('https://example.test/callback?'+label+'='+one+'&ok=1'); print('Cook'+'ie: '+'s'+'id='+two+'; theme=light', file=sys.stderr); print('Author'+'ization: Basic '+three, file=sys.stderr)",
                            ],
                            "captureStdout": True,
                            "captureStderr": True,
                            "evidenceType": "command",
                            "proves": "Runner evidence redacts secret-like stdout and stderr values.",
                        }
                    ],
                }
            ],
        },
    )
    redaction_env = {
        **os.environ,
        "QA_REDACT_ONE": "fixture-password",
        "QA_REDACT_TWO": "fixture-session",
        "QA_REDACT_THREE": "fixture-basic",
    }
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str((redaction_dir / "test-plan.json").resolve()),
            "--matrix",
            str((redaction_dir / "test-matrix.json").resolve()),
            "--summary",
            str((redaction_dir / "plan-audit-summary.json").resolve()),
        ],
        cwd=redaction_dir,
        env=redaction_env,
    )
    run_cmd(
        [
            "node",
            str(script_dir / "playwright_probe.mjs"),
            "--plan",
            str((redaction_dir / "test-plan.json").resolve()),
            "--plan-audit-summary",
            str((redaction_dir / "plan-audit-summary.json").resolve()),
        ],
        cwd=redaction_dir,
        env=redaction_env,
    )
    results = load_json(redaction_dir / "results.json")
    step = results.get("scenarios", [{}])[0].get("steps", [{}])[0]
    stdout_text = Path(step.get("stdoutPath")).read_text(encoding="utf-8")
    stderr_text = Path(step.get("stderrPath")).read_text(encoding="utf-8")
    combined = json.dumps(step, ensure_ascii=False) + "\n" + stdout_text + "\n" + stderr_text
    assert_true("fixture-password" not in combined, "Runner output should redact password-like values from previews and evidence files.")
    assert_true("fixture-session" not in combined, "Runner output should redact cookie values from previews and evidence files.")
    assert_true("fixture-basic" not in combined, "Runner output should redact authorization values from previews and evidence files.")
    assert_true("password=[REDACTED]" in combined, "Runner output should preserve password field shape with a redacted value.")
    assert_true("Cookie: [REDACTED]" in combined, "Runner output should preserve cookie header shape with a redacted value.")
    assert_true("Authorization: [REDACTED]" in combined, "Runner output should preserve authorization header shape with a redacted value.")


def run_evidence_layer_gate_fixture(script_dir: Path, tmp_path: Path) -> None:
    layer_dir = tmp_path / "evidence-layer-gate"
    layer_dir.mkdir(parents=True, exist_ok=True)
    (layer_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (layer_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (layer_dir / "screenshots" / "fallback.png").write_bytes(b"fake-png-placeholder")
    (layer_dir / "evidence" / "stream-messages.txt").write_text('{"type":"answer_done","answer":"QA_LAYER_MARKER"}\n', encoding="utf-8")
    (layer_dir / "evidence" / "session-response.json").write_text('{"answer":"QA_LAYER_MARKER"}\n', encoding="utf-8")
    (layer_dir / "evidence" / "persistence-stdout.json").write_text('{"status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream",
                "source": "fixture",
                "text": "The stream emits answer_done and returns the current-run marker.",
                "test_ids": ["T-stream"],
                "status": "Untested",
            },
            {
                "id": "R-api",
                "source": "fixture",
                "text": "The session API returns the current-run marker.",
                "test_ids": ["T-api"],
                "status": "Untested",
            },
            {
                "id": "R-persist",
                "source": "fixture",
                "text": "The persisted turn reaches completed.",
                "test_ids": ["T-persist"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-stream",
                "requirement_ids": ["R-stream"],
                "type": "stream",
                "expected": "WebSocket returns the current-run marker QA_LAYER_MARKER and answer_done.",
                "status": "Untested",
            },
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": "Session detail API response contains the current-run marker QA_LAYER_MARKER.",
                "status": "Untested",
            },
            {
                "id": "T-persist",
                "requirement_ids": ["R-persist"],
                "type": "persistence",
                "expected": "Read-only persistence helper observes completed.",
                "status": "Untested",
            },
        ],
    }
    write_json(layer_dir / "test-matrix.json", matrix)

    weak_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream", "source": "fixture", "text": matrix["requirements"][0]["text"], "test_ids": ["T-stream"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "R-api", "source": "fixture", "text": matrix["requirements"][1]["text"], "test_ids": ["T-api"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "R-persist", "source": "fixture", "text": matrix["requirements"][2]["text"], "test_ids": ["T-persist"], "status": "Passed", "evidence_ids": ["E-ui"]},
        ],
        "tests": [
            {"id": "T-stream", "requirement_ids": ["R-stream"], "type": "stream", "expected": matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "T-persist", "requirement_ids": ["R-persist"], "type": "persistence", "expected": matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
        ],
        "evidence": [
            {
                "id": "E-ui",
                "type": "screenshot",
                "path": "screenshots/fallback.png",
                "current_run": True,
                "assertions": ["Fallback text is visible in the UI."],
                "proves": "The UI shows fallback text containing a user prompt marker.",
            }
        ],
    }
    write_json(layer_dir / "weak-ledger.json", weak_ledger)
    weak_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "test-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-ledger.json"),
            "--summary",
            str(layer_dir / "weak-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_proc.returncode != 0, "Weak UI/fallback evidence must not pass stream/API/persistence layer audit.")
    weak_audit = load_json(layer_dir / "weak-audit-summary.json")
    weak_errors = "\n".join(weak_audit.get("errors", []))
    assert_true("no WebSocket/SSE evidence" in weak_errors, "Stream tests should require WebSocket/SSE evidence.")
    assert_true("returned marker evidence" in weak_errors, "Current-run marker claims should require returned marker evidence.")
    assert_true("no persistence/log/API evidence" in weak_errors, "Persistence tests should require persistence/log/API evidence.")

    weak_stream_message_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream-message",
                "source": "fixture",
                "text": "The WebSocket stream emits an assistant message.",
                "test_ids": ["T-stream-message"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-stream-message",
                "requirement_ids": ["R-stream-message"],
                "type": "stream",
                "expected": "WebSocket evidence captures at least one assistant message.",
                "status": "Untested",
            }
        ],
    }
    write_json(layer_dir / "weak-stream-message-matrix.json", weak_stream_message_matrix)
    weak_stream_message_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-message", "source": "fixture", "text": weak_stream_message_matrix["requirements"][0]["text"], "test_ids": ["T-stream-message"], "status": "Passed", "evidence_ids": ["E-stream-assertion-only"]}
        ],
        "tests": [
            {"id": "T-stream-message", "requirement_ids": ["R-stream-message"], "type": "stream", "expected": weak_stream_message_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-assertion-only"]}
        ],
        "evidence": [
            {
                "id": "E-stream-assertion-only",
                "type": "websocket",
                "current_run": True,
                "messages_seen": 0,
                "assertions": ["The stream emitted an assistant message."],
                "requirement_ids": ["R-stream-message"],
                "test_ids": ["T-stream-message"],
                "proves": "A WebSocket assistant message was observed.",
            }
        ],
    }
    write_json(layer_dir / "weak-stream-message-ledger.json", weak_stream_message_ledger)
    weak_stream_message_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-stream-message-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-stream-message-ledger.json"),
            "--summary",
            str(layer_dir / "weak-stream-message-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_stream_message_proc.returncode != 0, "Stream pass claims must not pass from zero messages plus hand-written assertions.")
    weak_stream_message_audit = load_json(layer_dir / "weak-stream-message-audit-summary.json")
    assert_true("lacks captured stream message evidence" in "\n".join(weak_stream_message_audit.get("errors", [])), "Stream message audit should reject zero-message/assertion-only WebSocket evidence.")

    missing_stream_message_path_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-message", "source": "fixture", "text": weak_stream_message_matrix["requirements"][0]["text"], "test_ids": ["T-stream-message"], "status": "Passed", "evidence_ids": ["E-stream-missing-message-path"]}
        ],
        "tests": [
            {"id": "T-stream-message", "requirement_ids": ["R-stream-message"], "type": "stream", "expected": weak_stream_message_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-missing-message-path"]}
        ],
        "evidence": [
            {
                "id": "E-stream-missing-message-path",
                "type": "websocket",
                "url": "ws://fixture/stream",
                "messages_path": "evidence/missing-stream-messages.ndjson",
                "current_run": True,
                "assertions": ["The stream emitted an assistant message."],
                "requirement_ids": ["R-stream-message"],
                "test_ids": ["T-stream-message"],
                "proves": "A WebSocket assistant message was observed.",
            }
        ],
    }
    write_json(layer_dir / "missing-stream-message-path-ledger.json", missing_stream_message_path_ledger)
    missing_stream_message_path_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-stream-message-matrix.json"),
            "--ledger",
            str(layer_dir / "missing-stream-message-path-ledger.json"),
            "--summary",
            str(layer_dir / "missing-stream-message-path-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(missing_stream_message_path_proc.returncode != 0, "Stream pass claims must not pass from a missing messages_path artifact.")
    missing_stream_message_path_audit = load_json(layer_dir / "missing-stream-message-path-audit-summary.json")
    missing_stream_message_path_errors = "\n".join(missing_stream_message_path_audit.get("errors", []))
    assert_true("messages_path is missing" in missing_stream_message_path_errors, "Stream message audit should name missing messages_path artifacts.")
    assert_true("lacks captured stream message evidence" in missing_stream_message_path_errors, "Missing messages_path should not count as captured stream message evidence.")

    weak_json_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api-marker",
                "source": "fixture",
                "text": "The API returns the current-run marker.",
                "test_ids": ["T-api-marker"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-api-marker",
                "requirement_ids": ["R-api-marker"],
                "type": "api",
                "expected": "API response contains QA_JSON_MARKER.",
                "status": "Untested",
            }
        ],
    }
    write_json(layer_dir / "weak-json-matrix.json", weak_json_matrix)
    weak_json_ledger = {
        "schema_version": 2,
        "runtime_summary": {"qa_marker": "QA_JSON_MARKER"},
        "requirements": [
            {"id": "R-api-marker", "source": "fixture", "text": weak_json_matrix["requirements"][0]["text"], "test_ids": ["T-api-marker"], "status": "Passed", "evidence_ids": ["E-api-json"]}
        ],
        "tests": [
            {"id": "T-api-marker", "requirement_ids": ["R-api-marker"], "type": "api", "expected": weak_json_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-api-json"]}
        ],
        "evidence": [
            {
                "id": "E-api-json",
                "type": "api_response",
                "url": "/api/v1/echo",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "requirement_ids": ["R-api-marker"],
                "test_ids": ["T-api-marker"],
                "proves": "The API returned the current-run marker.",
            }
        ],
    }
    write_json(layer_dir / "weak-json-ledger.json", weak_json_ledger)
    weak_json_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-json-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-json-ledger.json"),
            "--summary",
            str(layer_dir / "weak-json-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_json_proc.returncode != 0, "Non-marker checked_json must not satisfy marker-return claims.")
    weak_json_audit = load_json(layer_dir / "weak-json-audit-summary.json")
    assert_true("returned marker evidence" in "\n".join(weak_json_audit.get("errors", [])), "Marker-return audit should reject checked_json that lacks the runtime marker.")

    self_proving_json_ledger = {
        "schema_version": 2,
        "runtime_summary": {"qa_marker": "QA_JSON_MARKER"},
        "requirements": [
            {"id": "R-api-marker", "source": "fixture", "text": weak_json_matrix["requirements"][0]["text"], "test_ids": ["T-api-marker"], "status": "Passed", "evidence_ids": ["E-api-json-self-proof"]}
        ],
        "tests": [
            {"id": "T-api-marker", "requirement_ids": ["R-api-marker"], "type": "api", "expected": "API response contains QA_JSON_MARKER and completed.", "status": "Passed", "evidence_ids": ["E-api-json-self-proof"]}
        ],
        "evidence": [
            {
                "id": "E-api-json-self-proof",
                "type": "api_response",
                "url": "/api/v1/echo",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"answer": "QA_JSON_MARKER", "status": "completed"},
                "assertions": [
                    "HTTP status observed: 200",
                    "JSON answer matched observed value QA_JSON_MARKER",
                    "JSON status matched observed value completed",
                ],
                "requirement_ids": ["R-api-marker"],
                "test_ids": ["T-api-marker"],
                "proves": "The API returned the current-run marker and completed terminal state.",
            }
        ],
    }
    write_json(layer_dir / "self-proving-json-ledger.json", self_proving_json_ledger)
    self_proving_json_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-json-matrix.json"),
            "--ledger",
            str(layer_dir / "self-proving-json-ledger.json"),
            "--summary",
            str(layer_dir / "self-proving-json-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(self_proving_json_proc.returncode != 0, "checked_json marker/terminal claims must not pass without a source response artifact.")
    self_proving_json_audit = load_json(layer_dir / "self-proving-json-audit-summary.json")
    assert_true("no referenced checked JSON artifact path" in "\n".join(self_proving_json_audit.get("errors", [])), "JSON audit should reject checked_json self-proof without a source artifact path.")

    weak_terminal_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream-terminal",
                "source": "fixture",
                "text": "The stream emits answer_done.",
                "test_ids": ["T-stream-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-persist-terminal",
                "source": "fixture",
                "text": "The persisted turn reaches completed.",
                "test_ids": ["T-persist-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-api-terminal",
                "source": "fixture",
                "text": "The same-session API read reaches completed.",
                "test_ids": ["T-api-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-ui-api-terminal",
                "source": "fixture",
                "text": "The click-triggered API response reaches completed.",
                "test_ids": ["T-ui-api-terminal"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-stream-terminal",
                "requirement_ids": ["R-stream-terminal"],
                "type": "stream",
                "expected": "WebSocket evidence includes answer_done.",
                "status": "Untested",
            },
            {
                "id": "T-persist-terminal",
                "requirement_ids": ["R-persist-terminal"],
                "type": "persistence",
                "expected": "Read-only persistence evidence shows completed.",
                "status": "Untested",
            },
            {
                "id": "T-api-terminal",
                "requirement_ids": ["R-api-terminal"],
                "type": "api",
                "expected": "API response JSON shows completed.",
                "status": "Untested",
            },
            {
                "id": "T-ui-api-terminal",
                "requirement_ids": ["R-ui-api-terminal"],
                "type": "ui_to_api",
                "expected": "Click-to-response evidence shows completed.",
                "status": "Untested",
            },
        ],
    }
    write_json(layer_dir / "weak-terminal-matrix.json", weak_terminal_matrix)
    weak_terminal_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][0]["text"], "test_ids": ["T-stream-terminal"], "status": "Passed", "evidence_ids": ["E-stream-terminal"]},
            {"id": "R-persist-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][1]["text"], "test_ids": ["T-persist-terminal"], "status": "Passed", "evidence_ids": ["E-persist-terminal"]},
            {"id": "R-api-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][2]["text"], "test_ids": ["T-api-terminal"], "status": "Passed", "evidence_ids": ["E-api-terminal"]},
            {"id": "R-ui-api-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][3]["text"], "test_ids": ["T-ui-api-terminal"], "status": "Passed", "evidence_ids": ["E-ui-api-terminal"]},
        ],
        "tests": [
            {"id": "T-stream-terminal", "requirement_ids": ["R-stream-terminal"], "type": "stream", "expected": weak_terminal_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-terminal"]},
            {"id": "T-persist-terminal", "requirement_ids": ["R-persist-terminal"], "type": "persistence", "expected": weak_terminal_matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-persist-terminal"]},
            {"id": "T-api-terminal", "requirement_ids": ["R-api-terminal"], "type": "api", "expected": weak_terminal_matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-api-terminal"]},
            {"id": "T-ui-api-terminal", "requirement_ids": ["R-ui-api-terminal"], "type": "ui_to_api", "expected": weak_terminal_matrix["tests"][3]["expected"], "status": "Passed", "evidence_ids": ["E-ui-api-terminal"]},
        ],
        "evidence": [
            {
                "id": "E-stream-terminal",
                "type": "websocket",
                "current_run": True,
                "messages_seen": 1,
                "assertions": ["The stream returned answer_done."],
                "proves": "The stream reached answer_done terminal status.",
            },
            {
                "id": "E-persist-terminal",
                "type": "command",
                "current_run": True,
                "exit_code": 0,
                "assertions": ["The persistence helper saw completed."],
                "proves": "The persisted turn reached completed terminal status.",
            },
            {
                "id": "E-api-terminal",
                "type": "api_response",
                "current_run": True,
                "status_code": 200,
                "assertions": ["HTTP status observed: 200"],
                "requirement_ids": ["R-api-terminal"],
                "test_ids": ["T-api-terminal"],
                "proves": "The same-session API returned completed terminal status.",
            },
            {
                "id": "E-ui-api-terminal",
                "type": "ui_to_api",
                "current_run": True,
                "status_code": 200,
                "assertions": ["Click response status observed: 200"],
                "requirement_ids": ["R-ui-api-terminal"],
                "test_ids": ["T-ui-api-terminal"],
                "proves": "The click-triggered API returned completed terminal status.",
            },
        ],
    }
    write_json(layer_dir / "weak-terminal-ledger.json", weak_terminal_ledger)
    weak_terminal_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-terminal-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-terminal-ledger.json"),
            "--summary",
            str(layer_dir / "weak-terminal-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_terminal_proc.returncode != 0, "Terminal/completed claims must not pass from hand-written proves/assertions alone.")
    weak_terminal_audit = load_json(layer_dir / "weak-terminal-audit-summary.json")
    terminal_errors = "\n".join(weak_terminal_audit.get("errors", []))
    assert_true(terminal_errors.count("terminal-status evidence") >= 4, "Terminal audit should require returned/output terminal-status evidence for stream, API, UI-to-API, and persistence claims.")

    good_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream", "source": "fixture", "text": matrix["requirements"][0]["text"], "test_ids": ["T-stream"], "status": "Passed", "evidence_ids": ["E-stream"]},
            {"id": "R-api", "source": "fixture", "text": matrix["requirements"][1]["text"], "test_ids": ["T-api"], "status": "Passed", "evidence_ids": ["E-api"]},
            {"id": "R-persist", "source": "fixture", "text": matrix["requirements"][2]["text"], "test_ids": ["T-persist"], "status": "Passed", "evidence_ids": ["E-persist"]},
        ],
        "tests": [
            {"id": "T-stream", "requirement_ids": ["R-stream"], "type": "stream", "expected": matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream"]},
            {"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-api"]},
            {"id": "T-persist", "requirement_ids": ["R-persist"], "type": "persistence", "expected": matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-persist"]},
        ],
        "evidence": [
            {
                "id": "E-stream",
                "type": "websocket",
                "path": "evidence/stream-messages.txt",
                "current_run": True,
                "messages_seen": 2,
                "message_text_contains_matched": "QA_LAYER_MARKER",
                "checked_json": {"type": "answer_done"},
                "assertions": [
                    "WebSocket messages observed: 2",
                    "WebSocket message text contained expected text: QA_LAYER_MARKER",
                    "JSON type matched observed value answer_done",
                ],
                "proves": "The stream emitted answer_done and returned the current-run marker.",
            },
            {
                "id": "E-api",
                "type": "api_response",
                "url": "/api/v1/sessions/session-1",
                "body_path": "evidence/session-response.json",
                "current_run": True,
                "status_code": 200,
                "response_text_contains_matched": "QA_LAYER_MARKER",
                "assertions": ["HTTP status observed: 200", "Response text contained expected text: QA_LAYER_MARKER"],
                "proves": "The session API returned the current-run marker.",
            },
            {
                "id": "E-persist",
                "type": "command",
                "value": "exit_code=0",
                "stdout_path": "evidence/persistence-stdout.json",
                "current_run": True,
                "exit_code": 0,
                "stdout_contains_matched": "completed",
                "assertions": ["Command exit code observed: 0", "Stdout contained expected text: completed"],
                "proves": "The read-only persistence helper observed completed terminal status.",
            },
        ],
    }
    write_json(layer_dir / "good-ledger.json", good_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "test-matrix.json"),
            "--ledger",
            str(layer_dir / "good-ledger.json"),
            "--summary",
            str(layer_dir / "good-audit-summary.json"),
        ],
        cwd=layer_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(layer_dir / "good-ledger.json"),
            "--audit-summary",
            str(layer_dir / "good-audit-summary.json"),
            "--out",
            str(layer_dir / "good-verdict.json"),
            "--fail-on-not-pass",
        ],
        cwd=layer_dir,
    )
    good_verdict = load_json(layer_dir / "good-verdict.json")
    assert_true(good_verdict.get("can_claim_pass") is True, "Strong stream/API/persistence evidence should allow a pass verdict.")


def run_evidence_freshness_fixture(script_dir: Path, tmp_path: Path) -> None:
    fresh_dir = tmp_path / "evidence-freshness"
    fresh_dir.mkdir(parents=True, exist_ok=True)
    (fresh_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    stale_file = fresh_dir / "screenshots" / "stale.png"
    fresh_file = fresh_dir / "screenshots" / "fresh.png"
    stale_file.write_bytes(b"old-image")
    fresh_file.write_bytes(VALID_PNG_1X1)
    os.utime(stale_file, (1577836800, 1577836800))

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-fresh",
                "source": "fixture",
                "text": "The report must use a fresh screenshot artifact.",
                "test_ids": ["T-fresh"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-fresh",
                "requirement_ids": ["R-fresh"],
                "type": "ui",
                "expected": "A fresh screenshot artifact proves the visible result.",
                "status": "Untested",
            }
        ],
    }
    write_json(fresh_dir / "test-matrix.json", matrix)
    write_json(
        fresh_dir / "results.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(fresh_dir),
            "status": "passed",
            "startedAt": "2020-01-02T00:00:00+00:00",
            "finishedAt": "2020-01-02T00:00:01+00:00",
            "scenarios": [],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-fresh",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-fresh"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "tests": [
                {
                    "id": "T-fresh",
                    "requirement_ids": ["R-fresh"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "evidence": [
                {
                    "id": "E-shot",
                    "type": "screenshot",
                    "path": f"screenshots/{path_name}",
                    "current_run": True,
                    "assertions": ["Fresh screenshot artifact shows the visible result."],
                    "proves": "The visible result is shown in a fresh screenshot artifact.",
                }
            ],
        }

    write_json(fresh_dir / "stale-ledger.json", ledger_for("stale.png"))
    stale_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(fresh_dir / "test-matrix.json"),
            "--results",
            str(fresh_dir / "results.json"),
            "--ledger",
            str(fresh_dir / "stale-ledger.json"),
            "--summary",
            str(fresh_dir / "stale-audit-summary.json"),
        ],
        cwd=str(fresh_dir),
        text=True,
        capture_output=True,
    )
    assert_true(stale_proc.returncode != 0, "Stale current-run file evidence must fail audit.")
    stale_audit = load_json(fresh_dir / "stale-audit-summary.json")
    assert_true("predates results.startedAt" in "\n".join(stale_audit.get("errors", [])), "Freshness audit should name stale file evidence.")

    write_json(fresh_dir / "fresh-ledger.json", ledger_for("fresh.png"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(fresh_dir / "test-matrix.json"),
            "--results",
            str(fresh_dir / "results.json"),
            "--ledger",
            str(fresh_dir / "fresh-ledger.json"),
            "--summary",
            str(fresh_dir / "fresh-audit-summary.json"),
        ],
        cwd=fresh_dir,
    )


def run_screenshot_integrity_fixture(script_dir: Path, tmp_path: Path) -> None:
    screenshot_dir = tmp_path / "screenshot-integrity"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    (screenshot_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    bad_file = screenshot_dir / "screenshots" / "placeholder.png"
    good_file = screenshot_dir / "screenshots" / "actual.png"
    bad_file.write_bytes(b"fake-png-placeholder")
    good_file.write_bytes(VALID_PNG_1X1)

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-shot",
                "source": "fixture",
                "text": "The report must cite a readable screenshot artifact.",
                "test_ids": ["T-shot"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-shot",
                "requirement_ids": ["R-shot"],
                "type": "ui",
                "expected": "A readable screenshot artifact proves the visible result.",
                "status": "Untested",
            }
        ],
    }
    write_json(screenshot_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-shot"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "evidence": [
                {
                    "id": "E-shot",
                    "type": "screenshot",
                    "path": f"screenshots/{path_name}",
                    "current_run": True,
                    "assertions": ["Screenshot artifact shows the visible result."],
                    "proves": "The visible result is shown in a readable screenshot artifact.",
                }
            ],
        }

    write_json(screenshot_dir / "bad-ledger.json", ledger_for("placeholder.png"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(screenshot_dir / "test-matrix.json"),
            "--ledger",
            str(screenshot_dir / "bad-ledger.json"),
            "--summary",
            str(screenshot_dir / "bad-audit-summary.json"),
        ],
        cwd=str(screenshot_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Placeholder screenshot bytes must fail screenshot integrity audit.")
    bad_audit = load_json(screenshot_dir / "bad-audit-summary.json")
    bad_errors = "\n".join(bad_audit.get("errors", []))
    assert_true("not a readable PNG/JPEG" in bad_errors, "Screenshot integrity audit should name unreadable images.")
    assert_true(bad_audit.get("screenshot_evidence_checked") == 1, "Screenshot integrity audit should count checked screenshot evidence.")

    write_json(screenshot_dir / "good-ledger.json", ledger_for("actual.png"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(screenshot_dir / "test-matrix.json"),
            "--ledger",
            str(screenshot_dir / "good-ledger.json"),
            "--summary",
            str(screenshot_dir / "good-audit-summary.json"),
        ],
        cwd=screenshot_dir,
    )
    good_audit = load_json(screenshot_dir / "good-audit-summary.json")
    assert_true(good_audit.get("screenshot_evidence_checked") == 1, "Readable screenshots should be counted by the audit.")


def run_text_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    text_dir = tmp_path / "text-artifact-assertions"
    text_dir.mkdir(parents=True, exist_ok=True)
    (text_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_messages = text_dir / "evidence" / "messages-good.txt"
    bad_messages = text_dir / "evidence" / "messages-bad.txt"
    good_messages.write_text('{"type":"answer_done","answer":"QA_TEXT_MARKER"}\n', encoding="utf-8")
    bad_messages.write_text('{"type":"answer_done","answer":"stale fallback text"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-text",
                "source": "fixture",
                "text": "The stream evidence file must contain the returned current-run marker.",
                "test_ids": ["T-text"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-text",
                "requirement_ids": ["R-text"],
                "type": "stream",
                "expected": "WebSocket evidence returns QA_TEXT_MARKER and answer_done.",
                "status": "Untested",
            }
        ],
    }
    write_json(text_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-text",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-text"],
                    "status": "Passed",
                    "evidence_ids": ["E-stream"],
                }
            ],
            "tests": [
                {
                    "id": "T-text",
                    "requirement_ids": ["R-text"],
                    "type": "stream",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-stream"],
                }
            ],
            "evidence": [
                {
                    "id": "E-stream",
                    "type": "websocket",
                    "path": f"evidence/{path_name}",
                    "messages_path": f"evidence/{path_name}",
                    "current_run": True,
                    "messages_seen": 1,
                    "message_text_contains_matched": "QA_TEXT_MARKER",
                    "checked_json": {"type": "answer_done"},
                    "assertions": [
                        "WebSocket messages observed: 1",
                        "WebSocket message text contained expected text: QA_TEXT_MARKER",
                        "JSON type matched observed value answer_done",
                    ],
                    "proves": "The stream returned the current-run marker and answer_done terminal event.",
                }
            ],
        }

    write_json(text_dir / "bad-ledger.json", ledger_for("messages-bad.txt"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(text_dir / "test-matrix.json"),
            "--ledger",
            str(text_dir / "bad-ledger.json"),
            "--summary",
            str(text_dir / "bad-audit-summary.json"),
        ],
        cwd=str(text_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Ledger text marker claims must fail when the artifact file does not contain the marker.")
    bad_audit = load_json(text_dir / "bad-audit-summary.json")
    assert_true("message_text_contains_matched" in "\n".join(bad_audit.get("errors", [])), "Text artifact audit should name the missing marker field.")
    assert_true(bad_audit.get("text_artifact_assertions_checked") == 1, "Text artifact audit should count checked text assertions.")

    write_json(text_dir / "good-ledger.json", ledger_for("messages-good.txt"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(text_dir / "test-matrix.json"),
            "--ledger",
            str(text_dir / "good-ledger.json"),
            "--summary",
            str(text_dir / "good-audit-summary.json"),
        ],
        cwd=text_dir,
    )
    good_audit = load_json(text_dir / "good-audit-summary.json")
    assert_true(good_audit.get("text_artifact_assertions_checked") == 1, "Matching text artifacts should be counted by the audit.")


def run_json_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    json_dir = tmp_path / "json-artifact-assertions"
    json_dir.mkdir(parents=True, exist_ok=True)
    (json_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_body = json_dir / "evidence" / "response-good.json"
    bad_body = json_dir / "evidence" / "response-bad.json"
    good_body.write_text('{"reply":"QA_JSON_MARKER","status":"completed"}\n', encoding="utf-8")
    bad_body.write_text('{"reply":"stale fallback","status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-json",
                "source": "fixture",
                "text": "The API body artifact must contain the checked current-run marker JSON.",
                "test_ids": ["T-json"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-json",
                "requirement_ids": ["R-json"],
                "type": "api",
                "expected": "API response JSON includes QA_JSON_MARKER.",
                "status": "Untested",
            }
        ],
    }
    write_json(json_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-json",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-json"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "tests": [
                {
                    "id": "T-json",
                    "requirement_ids": ["R-json"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "evidence": [
                {
                    "id": "E-api",
                    "type": "api_response",
                    "path": f"evidence/{path_name}",
                    "body_path": f"evidence/{path_name}",
                    "current_run": True,
                    "status_code": 200,
                    "checked_json": {"reply": "QA_JSON_MARKER", "status": "completed"},
                    "assertions": [
                        "HTTP status observed: 200",
                        "JSON reply matched observed value QA_JSON_MARKER",
                        "JSON status matched observed value completed",
                    ],
                    "proves": "The API response returned the current-run marker and completed status.",
                }
            ],
        }

    write_json(json_dir / "bad-ledger.json", ledger_for("response-bad.json"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(json_dir / "test-matrix.json"),
            "--ledger",
            str(json_dir / "bad-ledger.json"),
            "--summary",
            str(json_dir / "bad-audit-summary.json"),
        ],
        cwd=str(json_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Ledger checked_json claims must fail when the artifact JSON disagrees.")
    bad_audit = load_json(json_dir / "bad-audit-summary.json")
    assert_true("checked_json" in "\n".join(bad_audit.get("errors", [])), "JSON artifact audit should name the checked_json field.")
    assert_true(bad_audit.get("json_artifact_assertions_checked") == 1, "JSON artifact audit should count checked JSON assertions.")

    write_json(json_dir / "good-ledger.json", ledger_for("response-good.json"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(json_dir / "test-matrix.json"),
            "--ledger",
            str(json_dir / "good-ledger.json"),
            "--summary",
            str(json_dir / "good-audit-summary.json"),
        ],
        cwd=json_dir,
    )
    good_audit = load_json(json_dir / "good-audit-summary.json")
    assert_true(good_audit.get("json_artifact_assertions_checked") == 1, "Matching JSON artifacts should be counted by the audit.")


def run_api_body_defect_evidence_fixture(script_dir: Path, tmp_path: Path) -> None:
    body_dir = tmp_path / "api-body-defect-evidence"
    body_dir.mkdir(parents=True, exist_ok=True)
    body_path = body_dir / "evidence" / "api-body.txt"
    body_path.parent.mkdir(parents=True, exist_ok=True)
    response_body = '{"error":"fixture backend exploded","trace_id":"trace-fixture-1","access_token":"fixture-redacted"}'
    body_path.write_text(response_body, encoding="utf-8")
    write_json(
        body_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-api-body",
                    "source": "fixture",
                    "text": "API failures must preserve captured response body evidence.",
                    "test_ids": ["T-api-body"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-api-body",
                    "requirement_ids": ["R-api-body"],
                    "type": "api",
                    "expected": "GET /api/v1/body-fixture returns HTTP 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        body_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "failed",
            "artifactDir": str(body_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "api-body",
                    "status": "failed",
                    "steps": [
                        {
                            "scenarioId": "api-body",
                            "stepId": "T-api-body",
                            "testIds": ["T-api-body"],
                            "requirementIds": ["R-api-body"],
                            "action": "api",
                            "status": "failed",
                            "evidenceType": "api_response",
                            "proves": "The failed API response body is captured for root-cause evidence.",
                            "url": "http://127.0.0.1:9527/api/v1/body-fixture",
                            "method": "GET",
                            "statusCode": 500,
                            "bodyPreview": '{"error":"fixture backend exploded","trace_id":"trace-fixture-1","access_token":"[REDACTED]"}',
                            "bodyPath": str(body_path),
                            "error": "Expected status 200, got 500",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(
        body_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(body_dir),
            "scenarios": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(body_dir / "test-matrix.json"),
            "--results",
            str(body_dir / "results.json"),
            "--out",
            str(body_dir / "evidence-ledger.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(body_dir / "evidence-ledger.json"),
            "--results",
            str(body_dir / "results.json"),
            "--matrix",
            str(body_dir / "test-matrix.json"),
            "--out",
            str(body_dir / "defects.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(body_dir / "defects.json"),
            "--results",
            str(body_dir / "results.json"),
            "--ledger",
            str(body_dir / "evidence-ledger.json"),
            "--out",
            str(body_dir / "next-probes.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(body_dir),
            "--out",
            str(body_dir / "next-probe-preview.json"),
        ],
        cwd=body_dir,
    )
    ledger = load_json(body_dir / "evidence-ledger.json")
    defects = load_json(body_dir / "defects.json")
    next_probes = load_json(body_dir / "next-probes.json")
    preview = load_json(body_dir / "next-probe-preview.json")
    evidence = ledger.get("evidence", [{}])[0]
    finding = defects.get("findings", [{}])[0]
    finding_ref = finding.get("evidence", [{}])[0]
    log_recs = [rec for rec in next_probes.get("recommendations", []) if rec.get("objective") == "Correlate the captured trace/request id against local service logs."]
    assert_true(evidence.get("body_preview") and "fixture backend exploded" in evidence.get("body_preview", ""), "ledger should preserve captured API response body preview.")
    assert_true(evidence.get("body_path") == "evidence/api-body.txt", "ledger should preserve response body artifact path relative to the run dir.")
    assert_true(any("Response body preview observed" in item for item in evidence.get("assertions", [])), "ledger assertions should name response body preview evidence.")
    assert_true("response body: " in finding.get("actual", "") and "fixture backend exploded" in finding.get("actual", ""), "defect actual should include a bounded response body preview.")
    assert_true(finding_ref.get("body_path") == "evidence/api-body.txt", "defect evidence ref should keep the response body artifact path.")
    assert_true("access_token\":\"[REDACTED]" in finding_ref.get("body_preview", ""), "defect evidence ref should keep redacted body preview, not raw secret-like values.")
    assert_true(log_recs, "captured response-body trace_id should generate a log-correlation next-probe recommendation.")
    assert_true(log_recs[0].get("plan_step_hint", {}).get("env", {}).get("QA_TRACE_ID") == "trace-fixture-1", "log-correlation recommendation should pass the extracted trace id through env.")
    skipped_log = [item for item in preview.get("skipped_recommendations", []) if item.get("id") == log_recs[0].get("id")]
    assert_true(skipped_log and skipped_log[0].get("reason") == "command probe requires --allow-command-probes", "log-correlation command probes should remain behind the command safety gate by default.")


def run_extraction_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    extract_dir = tmp_path / "extraction-artifact-assertions"
    extract_dir.mkdir(parents=True, exist_ok=True)
    (extract_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_stdout = extract_dir / "evidence" / "stdout-good.json"
    bad_stdout = extract_dir / "evidence" / "stdout-bad.json"
    good_stdout.write_text('{"turn_id":"turn-1","status":"completed"}\n', encoding="utf-8")
    bad_stdout.write_text('{"turn_id":"turn-2","status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-extract",
                "source": "fixture",
                "text": "The extracted turn id must come from the stdout JSON artifact.",
                "test_ids": ["T-extract"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-extract",
                "requirement_ids": ["R-extract"],
                "type": "persistence",
                "expected": "stdout JSON extraction records turn_id=turn-1 from the artifact.",
                "status": "Untested",
            }
        ],
    }
    write_json(extract_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-extract",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-extract"],
                    "status": "Passed",
                    "evidence_ids": ["E-command"],
                }
            ],
            "tests": [
                {
                    "id": "T-extract",
                    "requirement_ids": ["R-extract"],
                    "type": "persistence",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-command"],
                }
            ],
            "evidence": [
                {
                    "id": "E-command",
                    "type": "command",
                    "path": f"evidence/{path_name}",
                    "stdout_path": f"evidence/{path_name}",
                    "current_run": True,
                    "exit_code": 0,
                    "checked_stdout_json": {"status": "completed"},
                    "extracted_stdout_json": {"turn_id": "turn-1"},
                    "extracted_stdout_json_paths": {"turn_id": "turn_id"},
                    "assertions": [
                        "Command exit code observed: 0",
                        "stdout JSON status matched observed value completed",
                        "Extracted stdout runtime variables: turn_id",
                    ],
                    "proves": "The read-only helper extracted turn_id from stdout JSON.",
                }
            ],
        }

    write_json(extract_dir / "bad-ledger.json", ledger_for("stdout-bad.json"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(extract_dir / "test-matrix.json"),
            "--ledger",
            str(extract_dir / "bad-ledger.json"),
            "--summary",
            str(extract_dir / "bad-audit-summary.json"),
        ],
        cwd=str(extract_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Extracted stdout JSON must fail when the source artifact disagrees.")
    bad_audit = load_json(extract_dir / "bad-audit-summary.json")
    assert_true("extracted_stdout_json.turn_id" in "\n".join(bad_audit.get("errors", [])), "Extraction audit should name the mismatched extracted variable.")
    assert_true(bad_audit.get("extraction_artifact_assertions_checked") == 1, "Extraction artifact audit should count checked extractions.")

    write_json(extract_dir / "good-ledger.json", ledger_for("stdout-good.json"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(extract_dir / "test-matrix.json"),
            "--ledger",
            str(extract_dir / "good-ledger.json"),
            "--summary",
            str(extract_dir / "good-audit-summary.json"),
        ],
        cwd=extract_dir,
    )
    good_audit = load_json(extract_dir / "good-audit-summary.json")
    assert_true(good_audit.get("extraction_artifact_assertions_checked") == 1, "Matching extraction artifacts should be counted by the audit.")


def run_response_header_consistency_fixture(script_dir: Path, tmp_path: Path) -> None:
    header_dir = tmp_path / "response-header-consistency"
    header_dir.mkdir(parents=True, exist_ok=True)
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-header",
                "source": "fixture",
                "text": "The checked and extracted trace header must match the captured response headers.",
                "test_ids": ["T-header"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-header",
                "requirement_ids": ["R-header"],
                "type": "api",
                "expected": "Captured response headers contain x-trace-id=trace-good.",
                "status": "Untested",
            }
        ],
    }
    write_json(header_dir / "test-matrix.json", matrix)

    def ledger_for(claimed_trace: str, *, include_response_headers: bool = True) -> dict[str, Any]:
        evidence = {
            "id": "E-header",
            "type": "api_response",
            "url": "/api/v1/trace",
            "current_run": True,
            "status_code": 200,
            "checked_response_headers": {"x-trace-id": claimed_trace},
            "extracted_response_headers": {"trace_id": claimed_trace},
            "extracted_response_header_names": {"trace_id": "x-trace-id"},
            "assertions": ["HTTP status observed: 200", "Response header x-trace-id matched observed value"],
            "proves": "The API response exposes a trace header.",
        }
        if include_response_headers:
            evidence["response_headers"] = {"content-type": "application/json", "x-trace-id": "trace-good"}
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-header",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-header"],
                    "status": "Passed",
                    "evidence_ids": ["E-header"],
                }
            ],
            "tests": [
                {
                    "id": "T-header",
                    "requirement_ids": ["R-header"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-header"],
                }
            ],
            "evidence": [evidence],
        }

    write_json(header_dir / "self-proving-ledger.json", ledger_for("trace-good", include_response_headers=False))
    self_proving_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "self-proving-ledger.json"),
            "--summary",
            str(header_dir / "self-proving-audit-summary.json"),
        ],
        cwd=str(header_dir),
        text=True,
        capture_output=True,
    )
    assert_true(self_proving_proc.returncode != 0, "Header claims must not pass without captured response_headers.")
    self_proving_audit = load_json(header_dir / "self-proving-audit-summary.json")
    assert_true("lacks captured response_headers" in "\n".join(self_proving_audit.get("errors", [])), "Header audit should reject response-header self-proof without captured headers.")

    write_json(header_dir / "bad-ledger.json", ledger_for("trace-bad"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "bad-ledger.json"),
            "--summary",
            str(header_dir / "bad-audit-summary.json"),
        ],
        cwd=str(header_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Checked/extracted response headers must fail when captured response_headers disagrees.")
    bad_audit = load_json(header_dir / "bad-audit-summary.json")
    assert_true("checked_response_headers.x-trace-id" in "\n".join(bad_audit.get("errors", [])), "Header audit should name checked response header mismatch.")
    assert_true(bad_audit.get("response_header_consistency_checked") == 2, "Header audit should count checked and extracted header consistency.")

    write_json(header_dir / "good-ledger.json", ledger_for("trace-good"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "good-ledger.json"),
            "--summary",
            str(header_dir / "good-audit-summary.json"),
        ],
        cwd=header_dir,
    )
    good_audit = load_json(header_dir / "good-audit-summary.json")
    assert_true(good_audit.get("response_header_consistency_checked") == 2, "Matching header evidence should be counted by the audit.")


def run_strategy_coverage_fixture(script_dir: Path, tmp_path: Path) -> None:
    strategy_dir = tmp_path / "strategy-coverage"
    strategy_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        strategy_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": "The settings page is visible.",
                    "test_ids": ["T-ui"],
                    "status": "Untested",
                },
                {
                    "id": "R-permission",
                    "source": "fixture",
                    "text": "Only admins can save restricted settings.",
                    "test_ids": ["T-permission"],
                    "status": "Blocked",
                    "notes": "Admin and non-admin auth states are not available in this fixture.",
                },
                {
                    "id": "R-permission-ui-only",
                    "source": "fixture",
                    "text": "Non-admin users cannot save restricted settings, not just open the settings page.",
                    "test_ids": ["T-permission-ui-only"],
                    "status": "Untested",
                },
                {
                    "id": "R-runtime-disposition",
                    "source": "fixture",
                    "text": "Runtime diagnostics must prove no failed HTTP responses or request failures remain in results.json.",
                    "test_ids": ["T-runtime-disposition"],
                    "status": "Untested",
                },
                {
                    "id": "R-list-interaction",
                    "source": "fixture",
                    "text": "Searching the inventory table must show an empty state without stale rows.",
                    "test_ids": ["T-list-interaction"],
                    "status": "Blocked",
                },
                {
                    "id": "R-session-api",
                    "source": "fixture",
                    "text": "The same session is readable through the session detail API and contains expected session payload.",
                    "test_ids": ["T-session-api"],
                    "status": "Untested",
                },
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": "Settings page is visible.",
                    "status": "Untested",
                },
                {
                    "id": "T-permission",
                    "requirement_ids": ["R-permission"],
                    "type": "permission",
                    "expected": "Admin is allowed and non-admin is denied.",
                    "status": "Blocked",
                    "notes": "Missing auth states for role coverage.",
                },
                {
                    "id": "T-permission-ui-only",
                    "requirement_ids": ["R-permission-ui-only"],
                    "type": "permission",
                    "expected": "Non-admin save denial must be proven by role-aware denial evidence.",
                    "status": "Untested",
                },
                {
                    "id": "T-runtime-disposition",
                    "requirement_ids": ["R-runtime-disposition"],
                    "type": "runtime",
                    "steps": ["Check failed response and request failure runtime arrays."],
                    "expected": "No failed HTTP responses or request failures remain in results.json runtime arrays.",
                    "required_evidence": ["runtime disposition probe", "results.json runtime arrays"],
                    "status": "Untested",
                },
                {
                    "id": "T-list-interaction",
                    "requirement_ids": ["R-list-interaction"],
                    "type": "interaction",
                    "steps": ["Exercise search controls and assert the empty-state row set."],
                    "expected": "List search controls show empty state without stale rows.",
                    "required_evidence": ["ui_interaction", "query_params", "empty_state", "stale_data_guard"],
                    "status": "Blocked",
                    "notes": "Generated as a blocked probe because required entrypoint, runtime data, credential, or safe test data is missing.",
                },
                {
                    "id": "T-session-api",
                    "requirement_ids": ["R-session-api"],
                    "type": "api",
                    "expected": "Session detail API returns expected session payload for the same session_id.",
                    "status": "Untested",
                },
            ],
        },
    )
    write_json(
        strategy_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(strategy_dir),
            "scenarios": [
                {
                    "id": "ui-only",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "T-ui-open",
                            "testIds": ["T-ui"],
                            "requirementIds": ["R-ui"],
                            "path": "/settings",
                            "evidenceType": "navigation",
                            "proves": "The settings page entry path opens.",
                        },
                        {
                            "action": "goto",
                            "id": "T-permission-ui-only-open",
                            "testIds": ["T-permission-ui-only"],
                            "requirementIds": ["R-permission-ui-only"],
                            "path": "/settings/restricted",
                            "evidenceType": "navigation",
                            "proves": "The restricted settings page opens.",
                        }
                    ],
                },
                {
                    "id": "runtime-only",
                    "steps": [
                        {
                            "action": "expectNoFailedResponses",
                            "id": "T-runtime-disposition",
                            "testIds": ["T-runtime-disposition"],
                            "requirementIds": ["R-runtime-disposition"],
                            "evidenceType": "runtime",
                            "proves": "No failed runtime responses remain in the current run.",
                        }
                    ],
                },
                {
                    "id": "session-api",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-session-api",
                            "testIds": ["T-session-api"],
                            "requirementIds": ["R-session-api"],
                            "method": "GET",
                            "path": "/api/v1/sessions/session_fixture",
                            "expectStatus": 200,
                            "captureBody": True,
                            "evidenceType": "api_response",
                            "proves": "The same session is readable through the API and contains expected session payload.",
                        }
                    ],
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(strategy_dir / "test-plan.json"),
            "--matrix",
            str(strategy_dir / "test-matrix.json"),
            "--summary",
            str(strategy_dir / "plan-audit-summary.json"),
        ],
        cwd=strategy_dir,
    )
    plan_audit = load_json(strategy_dir / "plan-audit-summary.json")
    strategy = plan_audit.get("strategy_coverage") or {}
    assert_true(plan_audit.get("passed") is True, "blocked strategy dimensions should not make the plan structurally invalid.")
    assert_true(plan_audit.get("coverage_sufficient") is False, "plan audit should expose strategy gaps as coverage_sufficient=false even when structure passed.")
    assert_true(plan_audit.get("coverage_gap_count") == strategy.get("gap_count"), "plan audit should mirror strategy gap count at the top level for gate consumers.")
    assert_true("ui" in strategy.get("covered_dimensions", []), "strategy coverage should mark UI as executable.")
    assert_true("ui" in strategy.get("observed_dimensions", []), "strategy coverage should separately expose observed executable UI probes.")
    dimensions = strategy.get("dimensions") or {}
    permission_dim = dimensions.get("permission") or {}
    assert_true(permission_dim.get("executable_count") == 0, "UI-only probes must not count as executable permission coverage.")
    assert_true("T-permission-ui-only" in permission_dim.get("test_ids", []), "UI-only permission test should remain a planned permission dimension.")
    assert_true("T-permission-ui-only" not in permission_dim.get("executable_test_ids", []), "UI-only permission test should not appear in permission executable_test_ids.")
    assert_true("T-list-interaction" not in permission_dim.get("test_ids", []), "generic blocked notes mentioning credentials must not create false permission strategy coverage.")
    ui_dim = dimensions.get("ui") or {}
    assert_true(ui_dim.get("incidental_executable_count", 0) >= 1, "UI-only probes for non-UI requirements should be counted as incidental UI execution.")
    assert_true("T-permission-ui-only" in ui_dim.get("observed_test_ids", []), "UI-only permission probe should be visible as observed UI execution.")
    runtime_dim = dimensions.get("runtime") or {}
    assert_true("T-runtime-disposition" in runtime_dim.get("executable_test_ids", []), "runtime disposition tests should stay executable runtime coverage.")
    assert_true("T-session-api" not in runtime_dim.get("test_ids", []), "plain session detail API should not create a runtime strategy requirement.")
    api_dim = dimensions.get("api") or {}
    assert_true("T-runtime-disposition" not in api_dim.get("test_ids", []), "runtime disposition wording about failed responses must not create a false API strategy requirement.")
    assert_true("T-session-api" in api_dim.get("executable_test_ids", []), "plain session detail API should remain executable API coverage.")
    analytics_dim = dimensions.get("analytics") or {}
    assert_true("T-session-api" not in analytics_dim.get("test_ids", []), "plain session_id API must not be classified as analytics telemetry.")
    gaps = strategy.get("gaps") or []
    assert_true(any(item.get("dimension") == "permission" for item in gaps), "strategy coverage should expose permission as a non-executable planned dimension.")
    assert_true(not any(item.get("dimension") == "api" and "T-runtime-disposition" in item.get("test_ids", []) for item in gaps), "runtime disposition tests should not produce false API strategy gaps.")

    write_json(
        strategy_dir / "evidence-ledger.json",
        {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": "The settings page is visible.",
                    "test_ids": ["T-ui"],
                    "status": "Passed",
                    "evidence_ids": ["E-ui"],
                },
                {
                    "id": "R-permission",
                    "source": "fixture",
                    "text": "Only admins can save restricted settings.",
                    "test_ids": ["T-permission"],
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Admin and non-admin auth states are not available in this fixture.",
                },
                {
                    "id": "R-permission-ui-only",
                    "source": "fixture",
                    "text": "Non-admin users cannot save restricted settings, not just open the settings page.",
                    "test_ids": ["T-permission-ui-only"],
                    "status": "Passed",
                    "evidence_ids": ["E-ui-only"],
                },
                {
                    "id": "R-runtime-disposition",
                    "source": "fixture",
                    "text": "Runtime diagnostics must prove no failed HTTP responses or request failures remain in results.json.",
                    "test_ids": ["T-runtime-disposition"],
                    "status": "Passed",
                    "evidence_ids": ["E-runtime"],
                },
                {
                    "id": "R-list-interaction",
                    "source": "fixture",
                    "text": "Searching the inventory table must show an empty state without stale rows.",
                    "test_ids": ["T-list-interaction"],
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Selector-aware list controls are not available in this fixture.",
                },
                {
                    "id": "R-session-api",
                    "source": "fixture",
                    "text": "The same session is readable through the session detail API and contains expected session payload.",
                    "test_ids": ["T-session-api"],
                    "status": "Passed",
                    "evidence_ids": ["E-session-api"],
                },
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": "Settings page is visible.",
                    "status": "Passed",
                    "evidence_ids": ["E-ui"],
                },
                {
                    "id": "T-permission",
                    "requirement_ids": ["R-permission"],
                    "type": "permission",
                    "expected": "Admin is allowed and non-admin is denied.",
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Missing auth states for role coverage.",
                },
                {
                    "id": "T-permission-ui-only",
                    "requirement_ids": ["R-permission-ui-only"],
                    "type": "permission",
                    "expected": "Non-admin save denial must be proven by role-aware denial evidence.",
                    "status": "Passed",
                    "evidence_ids": ["E-ui-only"],
                },
                {
                    "id": "T-runtime-disposition",
                    "requirement_ids": ["R-runtime-disposition"],
                    "type": "runtime",
                    "expected": "No failed HTTP responses or request failures remain in results.json runtime arrays.",
                    "status": "Passed",
                    "evidence_ids": ["E-runtime"],
                },
                {
                    "id": "T-list-interaction",
                    "requirement_ids": ["R-list-interaction"],
                    "type": "interaction",
                    "expected": "List search controls show empty state without stale rows.",
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Selector-aware list controls are not available in this fixture.",
                },
                {
                    "id": "T-session-api",
                    "requirement_ids": ["R-session-api"],
                    "type": "api",
                    "expected": "Session detail API returns expected session payload for the same session_id.",
                    "status": "Passed",
                    "evidence_ids": ["E-session-api"],
                },
            ],
            "evidence": [
                {
                    "id": "E-ui",
                    "type": "ui_assertion",
                    "value": "settings page visible",
                    "current_run": True,
                    "assertions": ["The settings page opened."],
                    "proves": "The settings page is visible.",
                },
                {
                    "id": "E-ui-only",
                    "type": "ui_assertion",
                    "value": "restricted settings page opened",
                    "current_run": True,
                    "assertions": ["The restricted settings page opened."],
                    "proves": "The restricted settings page is reachable.",
                },
                {
                    "id": "E-runtime",
                    "type": "runtime",
                    "value": "failed_responses=0 request_failures=0",
                    "current_run": True,
                    "assertions": ["No failed responses remain.", "No request failures remain."],
                    "proves": "Runtime failed response and request failure arrays are empty.",
                },
                {
                    "id": "E-session-api",
                    "type": "api_response",
                    "value": "status=200 expected session payload present for same session_id",
                    "current_run": True,
                    "status": "passed",
                    "test_ids": ["T-session-api"],
                    "requirement_ids": ["R-session-api"],
                    "assertions": ["Session detail returned 200.", "Expected session payload was present for the same session_id."],
                    "proves": "The session detail API returns expected session payload for the same session_id.",
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(strategy_dir / "test-matrix.json"),
            "--ledger",
            str(strategy_dir / "evidence-ledger.json"),
            "--summary",
            str(strategy_dir / "audit-summary.json"),
        ],
        cwd=strategy_dir,
    )
    verdict_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(strategy_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(strategy_dir / "audit-summary.json"),
            "--plan-audit-summary",
            str(strategy_dir / "plan-audit-summary.json"),
            "--out",
            str(strategy_dir / "qa-verdict.json"),
        ],
        cwd=strategy_dir,
        text=True,
        capture_output=True,
    )
    assert_true(verdict_proc.returncode == 0, "strategy coverage verdict generation should complete and write qa-verdict.json.")
    verdict = load_json(strategy_dir / "qa-verdict.json")
    reason_codes = {item.get("code") for item in verdict.get("reasons", []) if isinstance(item, dict)}
    assert_true("strategy_dimension_gap" in reason_codes, "verdict should expose non-executable strategy dimensions as a pass-blocking reason.")
    assert_true(verdict.get("gates", {}).get("strategy_coverage_sufficient") is False, "verdict gate should distinguish structural plan validation from insufficient strategy coverage.")
    assert_true(verdict.get("can_claim_pass") is False, "strategy dimension gaps should block final pass claims.")


def run_command_strategy_dimension_mapping_fixture(script_dir: Path, tmp_path: Path) -> None:
    strategy_dir = tmp_path / "command-strategy-dimension-mapping"
    strategy_dir.mkdir(parents=True, exist_ok=True)

    def run_case(case_name: str, step: dict[str, Any], *, test_type: str = "command", expected: str | None = None, required_evidence: list[str] | None = None) -> dict[str, Any]:
        case_dir = strategy_dir / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            case_dir / "test-matrix.json",
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R-command",
                        "source": "fixture",
                        "text": "The command validates loader logic, API JSON behavior, and DB persistence.",
                        "test_ids": ["T-command"],
                        "status": "Untested",
                    }
                ],
                "tests": [
                    {
                        "id": "T-command",
                        "requirement_ids": ["R-command"],
                        "type": test_type,
                        "expected": expected or "Validate loader logic, API JSON behavior, and DB persistence.",
                        **({"required_evidence": required_evidence} if required_evidence is not None else {}),
                        "status": "Untested",
                    }
                ],
            },
        )
        write_json(
            case_dir / "test-plan.json",
            {
                "schemaVersion": 2,
                "baseUrl": "http://127.0.0.1:9527",
                "artifactDir": str(case_dir),
                "scenarios": [
                    {
                        "id": case_name,
                        "steps": [step],
                    }
                ],
            },
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "validate_plan.py"),
                "--plan",
                str(case_dir / "test-plan.json"),
                "--matrix",
                str(case_dir / "test-matrix.json"),
                "--summary",
                str(case_dir / "plan-audit-summary.json"),
            ],
            cwd=case_dir,
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode == 0, f"{case_name} should remain structurally valid.")
        return load_json(case_dir / "plan-audit-summary.json")

    generic_summary = run_case(
        "generic-code-pr",
        {
            "action": "command",
            "id": "T-command-generic",
            "testIds": ["T-command"],
            "requirementIds": ["R-command"],
            "command": [sys.executable, "-c", "print('ok')"],
            "evidenceType": "code_pr",
            "proves": "Command completes successfully for code PR validation.",
        },
    )
    generic_gaps = generic_summary.get("strategy_coverage", {}).get("gaps", [])
    assert_true(generic_summary.get("coverage_sufficient") is False, "generic command evidence with strategy gaps should expose coverage_sufficient=false.")
    assert_true(any(item.get("dimension") == "api" for item in generic_gaps), "generic code_pr command evidence should not silently satisfy API coverage.")
    assert_true(any(item.get("dimension") == "persistence" for item in generic_gaps), "generic code_pr command evidence should not silently satisfy persistence coverage.")

    code_pr_summary = run_case(
        "code-pr-static-command",
        {
            "action": "command",
            "id": "T-command-code-pr",
            "testIds": ["T-command"],
            "requirementIds": ["R-command"],
            "command": ["git", "diff", "--check"],
            "evidenceType": "code_pr",
            "proves": "The PR validation command exits successfully.",
        },
        test_type="code_pr",
        expected="The PR diff has no whitespace or conflict-marker issues.",
        required_evidence=["command stdout/stderr", "changed file list", "static check exit code"],
    )
    code_pr_gaps = code_pr_summary.get("strategy_coverage", {}).get("gaps", [])
    assert_true(code_pr_summary.get("coverage_sufficient") is True, "code_pr command evidence should not create persistence strategy gaps from generic stdout/stderr wording.")
    assert_true(not any(item.get("dimension") == "persistence" for item in code_pr_gaps), "code_pr static command evidence must not be classified as persistence coverage.")

    mapped_summary = run_case(
        "explicit-dimensions",
        {
            "action": "command",
            "id": "T-command-explicit",
            "testIds": ["T-command"],
            "requirementIds": ["R-command"],
            "command": [sys.executable, "-c", "print('ok')"],
            "evidenceType": "code_pr",
            "proves": "Command completes successfully for code PR validation.",
            "strategyDimensions": ["logic", "api", "persistence"],
        },
    )
    mapped_strategy = mapped_summary.get("strategy_coverage") or {}
    mapped_dimensions = mapped_strategy.get("dimensions") or {}
    assert_true(mapped_summary.get("coverage_sufficient") is True, "explicit command strategy dimensions should expose coverage_sufficient=true.")
    assert_true(mapped_summary.get("coverage_gap_count") == 0, "covered command strategy dimensions should expose zero top-level coverage gaps.")
    assert_true(mapped_strategy.get("gap_count") == 0, "explicit command strategy dimensions should satisfy mapped logic/API/persistence coverage.")
    assert_true(
        all((mapped_dimensions.get(dim) or {}).get("executable_count") == 1 for dim in ("logic", "api", "persistence")),
        "explicit command strategy dimensions should create executable coverage for every declared dimension.",
    )


def run_generated_requirement_strategy_suffix_fixture(script_dir: Path, tmp_path: Path) -> None:
    strategy_dir = tmp_path / "generated-requirement-strategy-suffix"
    strategy_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        strategy_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-quota",
                    "source": "fixture",
                    "text": "POST /api/v1/usage/events uses quota_metering, usage_counter, and reset boundary behavior.",
                    "test_ids": ["T-stream", "T-quota"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-stream",
                    "requirement_ids": ["R-quota"],
                    "type": "websocket",
                    "expected": "The stream emits a terminal success event for: POST /api/v1/usage/events uses quota_metering, usage_counter, and reset boundary behavior.",
                    "status": "Blocked",
                    "required_evidence": ["captured stream messages", "terminal event", "runtime errors"],
                },
                {
                    "id": "T-quota",
                    "requirement_ids": ["R-quota"],
                    "type": "quota_metering",
                    "expected": "Usage quota metering satisfies requirement: POST /api/v1/usage/events uses quota_metering, usage_counter, and reset boundary behavior.",
                    "status": "Blocked",
                    "required_evidence": ["quota_metering", "usage_counter", "reset_boundary"],
                },
            ],
        },
    )
    write_json(
        strategy_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(strategy_dir),
            "scenarios": [
                {
                    "id": "runtime-check",
                    "steps": [
                        {
                            "action": "expectNoConsoleErrors",
                            "id": "T-stream-runtime",
                            "testIds": ["T-stream"],
                            "requirementIds": ["R-quota"],
                            "evidenceType": "runtime",
                            "proves": "Runtime console checks are clean for the stream probe.",
                        }
                    ],
                }
            ],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(strategy_dir / "test-plan.json"),
            "--matrix",
            str(strategy_dir / "test-matrix.json"),
            "--summary",
            str(strategy_dir / "plan-audit-summary.json"),
        ],
        cwd=strategy_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode == 0, "generated requirement strategy suffix fixture should remain structurally valid.")
    summary = load_json(strategy_dir / "plan-audit-summary.json")
    dimensions = (summary.get("strategy_coverage") or {}).get("dimensions") or {}
    quota_dimension = dimensions.get("quota_metering") or {}
    stream_dimension = dimensions.get("stream") or {}
    assert_true(
        quota_dimension.get("planned_count") == 1 and quota_dimension.get("test_ids") == ["T-quota"],
        "embedded generated requirement text should not broadcast quota_metering onto unrelated stream tests.",
    )
    assert_true(
        stream_dimension.get("planned_count") == 1 and stream_dimension.get("test_ids") == ["T-stream"],
        "stripping generated requirement text should preserve the stream test's own dimension.",
    )


def run_current_run_required_fixture(script_dir: Path, tmp_path: Path) -> None:
    current_dir = tmp_path / "current-run-required"
    current_dir.mkdir(parents=True, exist_ok=True)
    (current_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (current_dir / "evidence" / "current-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-current",
                "source": "fixture",
                "text": "Passed requirements must use current-run evidence.",
                "test_ids": ["T-current"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-current",
                "requirement_ids": ["R-current"],
                "type": "api",
                "expected": "A current-run API response proves the requirement.",
                "status": "Untested",
            }
        ],
    }
    write_json(current_dir / "test-matrix.json", matrix)

    def ledger_for(current_value: Any = None, include_field: bool = True) -> dict[str, Any]:
        evidence = {
            "id": "E-api",
            "type": "api_response",
            "url": "/api/v1/current",
            "body_path": "evidence/current-response.json",
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": "The API response proves the requirement.",
        }
        if include_field:
            evidence["current_run"] = current_value
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-current",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-current"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "tests": [
                {
                    "id": "T-current",
                    "requirement_ids": ["R-current"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "evidence": [evidence],
        }

    for name, ledger in (
        ("missing-current-run", ledger_for(include_field=False)),
        ("false-current-run", ledger_for(False)),
    ):
        ledger_path = current_dir / f"{name}.json"
        summary_path = current_dir / f"{name}-audit-summary.json"
        write_json(ledger_path, ledger)
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "audit_evidence.py"),
                "--matrix",
                str(current_dir / "test-matrix.json"),
                "--ledger",
                str(ledger_path),
                "--summary",
                str(summary_path),
            ],
            cwd=str(current_dir),
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode != 0, f"{name} should fail current-run evidence audit.")
        audit = load_json(summary_path)
        assert_true("current_run=true" in "\n".join(audit.get("errors", [])), f"{name} audit should name current_run requirement.")

    write_json(current_dir / "good-ledger.json", ledger_for(True))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(current_dir / "test-matrix.json"),
            "--ledger",
            str(current_dir / "good-ledger.json"),
            "--summary",
            str(current_dir / "good-audit-summary.json"),
        ],
        cwd=current_dir,
    )


def run_secret_like_ledger_audit_fixture(script_dir: Path, tmp_path: Path) -> None:
    secret_dir = tmp_path / "secret-like-ledger-audit"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (secret_dir / "evidence" / "redacted-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(
        secret_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-secret-audit",
                    "source": "fixture",
                    "text": "Final evidence audit must reject raw credential material before reporting.",
                    "test_ids": ["T-secret-audit"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-secret-audit",
                    "requirement_ids": ["R-secret-audit"],
                    "type": "api",
                    "steps": ["Audit a passed ledger that includes API evidence."],
                    "expected": "Raw password, Cookie, or Authorization material is blocked before report generation.",
                    "required_evidence": ["audit error", "secret-like field location"],
                    "status": "Untested",
                }
            ],
        },
    )

    def ledger_with(url_value: str, assertion_value: str, proves_value: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-secret-audit",
                    "source": "fixture",
                    "text": "Final evidence audit must reject raw credential material before reporting.",
                    "test_ids": ["T-secret-audit"],
                    "status": "Passed",
                    "evidence_ids": ["E-secret-audit"],
                }
            ],
            "tests": [
                {
                    "id": "T-secret-audit",
                    "requirement_ids": ["R-secret-audit"],
                    "type": "api",
                    "expected": "Raw password, Cookie, or Authorization material is blocked before report generation.",
                    "status": "Passed",
                    "evidence_ids": ["E-secret-audit"],
                }
            ],
            "evidence": [
                {
                    "id": "E-secret-audit",
                    "type": "api_response",
                    "current_run": True,
                    "url": url_value,
                    "body_path": "evidence/redacted-response.json",
                    "status_code": 200,
                    "checked_json": {"ok": True},
                    "assertions": [assertion_value, "HTTP status observed: 200", "JSON ok matched observed value true"],
                    "proves": proves_value,
                }
            ],
        }

    raw_ledger = secret_dir / "raw-secret-ledger.json"
    write_json(
        raw_ledger,
        ledger_with(
            "https://example.test/callback?password=fixture-password&ok=1",
            "Authorization: Basic fixture-basic",
            "Cookie: sid=fixture-session; theme=light",
        ),
    )
    raw_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(secret_dir / "test-matrix.json"),
            "--ledger",
            str(raw_ledger),
            "--summary",
            str(secret_dir / "raw-secret-audit-summary.json"),
        ],
        cwd=str(secret_dir),
        text=True,
        capture_output=True,
    )
    assert_true(raw_proc.returncode != 0, "raw password/cookie/authorization material should fail evidence audit.")
    raw_audit = load_json(secret_dir / "raw-secret-audit-summary.json")
    raw_errors = "\n".join(raw_audit.get("errors", []))
    assert_true("Secret-like value found in ledger" in raw_errors, "raw secret audit should name secret-like ledger values.")
    assert_true("evidence[0].url" in raw_errors, "raw secret audit should identify URL/query secret location.")
    assert_true("evidence[0].assertions[0]" in raw_errors, "raw secret audit should identify Authorization assertion location.")
    assert_true("evidence[0].proves" in raw_errors, "raw secret audit should identify Cookie proof location.")

    write_json(
        secret_dir / "redacted-ledger.json",
        ledger_with(
            "https://example.test/callback?password=[REDACTED]&ok=1",
            "Authorization: [REDACTED]",
            "Cookie: [REDACTED]",
        ),
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(secret_dir / "test-matrix.json"),
            "--ledger",
            str(secret_dir / "redacted-ledger.json"),
            "--summary",
            str(secret_dir / "redacted-audit-summary.json"),
        ],
        cwd=secret_dir,
    )


def run_evidence_disposition_gate_fixture(script_dir: Path, tmp_path: Path) -> None:
    disposition_dir = tmp_path / "evidence-disposition-gate"
    disposition_dir.mkdir(parents=True, exist_ok=True)
    (disposition_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (disposition_dir / "evidence" / "disposition-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(
        disposition_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-disposition",
                    "source": "fixture",
                    "text": "A passed requirement cannot be proven by skipped or blocked evidence.",
                    "test_ids": ["T-disposition"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-disposition",
                    "requirement_ids": ["R-disposition"],
                    "type": "api",
                    "steps": ["Audit evidence disposition before allowing pass."],
                    "expected": "Only pass-disposition current-run evidence can support a passed test.",
                    "required_evidence": ["current-run API evidence", "pass-disposition status"],
                    "status": "Untested",
                }
            ],
        },
    )

    def ledger_with(evidence_status: str, *, skipped: bool = False) -> dict[str, Any]:
        evidence = {
            "id": "E-disposition",
            "type": "api_response",
            "current_run": True,
            "status": evidence_status,
            "url": "/api/v1/disposition",
            "body_path": "evidence/disposition-response.json",
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": "The API response proves the requirement.",
            "test_ids": ["T-disposition"],
            "requirement_ids": ["R-disposition"],
        }
        if skipped:
            evidence["skipped"] = True
            evidence["skip_reason"] = "Skipped because an earlier setup step failed."
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-disposition",
                    "source": "fixture",
                    "text": "A passed requirement cannot be proven by skipped or blocked evidence.",
                    "test_ids": ["T-disposition"],
                    "status": "Passed",
                    "evidence_ids": ["E-disposition"],
                }
            ],
            "tests": [
                {
                    "id": "T-disposition",
                    "requirement_ids": ["R-disposition"],
                    "type": "api",
                    "expected": "Only pass-disposition current-run evidence can support a passed test.",
                    "status": "Passed",
                    "evidence_ids": ["E-disposition"],
                }
            ],
            "evidence": [evidence],
        }

    write_json(disposition_dir / "skipped-ledger.json", ledger_with("skipped", skipped=True))
    skipped_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(disposition_dir / "test-matrix.json"),
            "--ledger",
            str(disposition_dir / "skipped-ledger.json"),
            "--summary",
            str(disposition_dir / "skipped-audit-summary.json"),
        ],
        cwd=str(disposition_dir),
        text=True,
        capture_output=True,
    )
    assert_true(skipped_proc.returncode != 0, "Passed ledger must fail when it cites skipped evidence.")
    skipped_audit = load_json(disposition_dir / "skipped-audit-summary.json")
    skipped_errors = "\n".join(skipped_audit.get("errors", []))
    assert_true("non-pass evidence E-disposition" in skipped_errors, "Audit should name non-pass evidence disposition.")
    assert_true("Requirement R-disposition" in skipped_errors, "Audit should block passed requirement with skipped evidence.")
    assert_true("Test T-disposition" in skipped_errors, "Audit should block passed test with skipped evidence.")

    write_json(disposition_dir / "passed-ledger.json", ledger_with("passed"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(disposition_dir / "test-matrix.json"),
            "--ledger",
            str(disposition_dir / "passed-ledger.json"),
            "--summary",
            str(disposition_dir / "passed-audit-summary.json"),
        ],
        cwd=disposition_dir,
    )


def run_evidence_lineage_fixture(script_dir: Path, tmp_path: Path) -> None:
    lineage_dir = tmp_path / "evidence-lineage"
    lineage_dir.mkdir(parents=True, exist_ok=True)
    (lineage_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (lineage_dir / "evidence" / "lineage-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-a",
                "source": "fixture",
                "text": "Requirement A must be proven by test A evidence.",
                "test_ids": ["T-a"],
                "status": "Untested",
            },
            {
                "id": "R-b",
                "source": "fixture",
                "text": "Requirement B must be proven by test B evidence.",
                "test_ids": ["T-b"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-a",
                "requirement_ids": ["R-a"],
                "type": "api",
                "expected": "API response A returns ok=true.",
                "status": "Untested",
            },
            {
                "id": "T-b",
                "requirement_ids": ["R-b"],
                "type": "api",
                "expected": "API response B returns ok=true.",
                "status": "Untested",
            },
        ],
    }
    write_json(lineage_dir / "test-matrix.json", matrix)

    def ledger_for(evidence_id: str, ev_req_id: str, ev_test_id: str, *, include_lineage: bool = True, generated_by: str = "ledger_from_probe.py") -> dict[str, Any]:
        evidence = {
            "id": evidence_id,
            "type": "api_response",
            "url": f"/api/{ev_test_id}",
            "body_path": "evidence/lineage-response.json",
            "generated_by": generated_by,
            "current_run": True,
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": f"Evidence for {ev_req_id}/{ev_test_id} returned ok=true.",
        }
        if include_lineage:
            evidence["test_ids"] = [ev_test_id]
            evidence["requirement_ids"] = [ev_req_id]
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-a",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-a"],
                    "status": "Passed",
                    "evidence_ids": [evidence_id],
                },
                {
                    "id": "R-b",
                    "source": "fixture",
                    "text": matrix["requirements"][1]["text"],
                    "test_ids": ["T-b"],
                    "status": "Untested",
                    "evidence_ids": [],
                    "notes": "Not part of this fixture pass claim.",
                },
            ],
            "tests": [
                {
                    "id": "T-a",
                    "requirement_ids": ["R-a"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": [evidence_id],
                },
                {
                    "id": "T-b",
                    "requirement_ids": ["R-b"],
                    "type": "api",
                    "expected": matrix["tests"][1]["expected"],
                    "status": "Untested",
                    "evidence_ids": [],
                    "notes": "Not part of this fixture pass claim.",
                },
            ],
            "evidence": [evidence],
        }

    write_json(lineage_dir / "bad-ledger.json", ledger_for("E-b", "R-b", "T-b"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "bad-ledger.json"),
            "--summary",
            str(lineage_dir / "bad-audit-summary.json"),
        ],
        cwd=str(lineage_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Mismatched evidence lineage must fail the audit.")
    bad_audit = load_json(lineage_dir / "bad-audit-summary.json")
    bad_errors = "\n".join(bad_audit.get("errors", []))
    assert_true("Passed requirement R-a references evidence E-b" in bad_errors, "Lineage audit should name the wrong requirement citation.")
    assert_true("Passed test T-a references evidence E-b" in bad_errors, "Lineage audit should name the wrong test citation.")
    assert_true(bad_audit.get("evidence_lineage_checked") == 2, "Lineage audit should count checked passed citations.")

    write_json(lineage_dir / "missing-runner-lineage-ledger.json", ledger_for("E-a", "R-a", "T-a", include_lineage=False))
    missing_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "missing-runner-lineage-ledger.json"),
            "--summary",
            str(lineage_dir / "missing-runner-lineage-audit-summary.json"),
        ],
        cwd=str(lineage_dir),
        text=True,
        capture_output=True,
    )
    assert_true(missing_proc.returncode != 0, "Bundled-runner evidence without lineage must fail the audit.")
    missing_audit = load_json(lineage_dir / "missing-runner-lineage-audit-summary.json")
    missing_errors = "\n".join(missing_audit.get("errors", []))
    assert_true("bundled-runner evidence E-a without test_ids/requirement_ids lineage" in missing_errors, "Audit should name missing bundled-runner lineage.")

    write_json(lineage_dir / "manual-no-lineage-ledger.json", ledger_for("E-manual", "R-a", "T-a", include_lineage=False, generated_by="manual"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "manual-no-lineage-ledger.json"),
            "--summary",
            str(lineage_dir / "manual-no-lineage-audit-summary.json"),
        ],
        cwd=lineage_dir,
    )
    manual_audit = load_json(lineage_dir / "manual-no-lineage-audit-summary.json")
    assert_true(manual_audit.get("evidence_lineage_warning_count") == 2, "Manual evidence without lineage should remain a warning, not a hard failure.")

    write_json(lineage_dir / "good-ledger.json", ledger_for("E-a", "R-a", "T-a"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "good-ledger.json"),
            "--summary",
            str(lineage_dir / "good-audit-summary.json"),
        ],
        cwd=lineage_dir,
    )
    good_audit = load_json(lineage_dir / "good-audit-summary.json")
    assert_true(good_audit.get("evidence_lineage_checked") == 2, "Matching evidence lineage should be counted by the audit.")


def run_runner_result_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    binding_dir = tmp_path / "runner-result-binding"
    binding_dir.mkdir(parents=True, exist_ok=True)
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-ui",
                "source": "fixture",
                "text": "Ready text must be visible in the current runner results.",
                "test_ids": ["T-ui"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-ui",
                "requirement_ids": ["R-ui"],
                "type": "ui",
                "expected": "Ready text is visible.",
                "status": "Untested",
            }
        ],
    }

    def ledger_for(*, scenario_id: str = "ui", status: str = "passed") -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-ui"],
                    "status": "Passed",
                    "evidence_ids": ["E-runner"],
                }
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-runner"],
                }
            ],
            "evidence": [
                {
                    "id": "E-runner",
                    "type": "ui_assertion",
                    "current_run": True,
                    "generated_by": "ledger_from_probe.py",
                    "scenario_id": scenario_id,
                    "step_id": "T-ui",
                    "action": "expectText",
                    "status": status,
                    "test_ids": ["T-ui"],
                    "requirement_ids": ["R-ui"],
                    "proves": "Ready text was visible.",
                    "value": "Ready",
                    "count": 1,
                }
            ],
        }

    good_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(binding_dir),
        "scenarios": [
            {
                "id": "ui",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "ui",
                        "stepId": "T-ui",
                        "testIds": ["T-ui"],
                        "requirementIds": ["R-ui"],
                        "action": "expectText",
                        "status": "passed",
                        "evidenceType": "ui_assertion",
                        "count": 1,
                        "proves": "Ready text was visible.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    write_json(binding_dir / "test-matrix.json", matrix)
    write_json(binding_dir / "good-results.json", good_results)
    write_json(binding_dir / "good-ledger.json", ledger_for())
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "good-results.json"),
            "--summary",
            str(binding_dir / "good-audit-summary.json"),
        ],
        cwd=binding_dir,
    )
    good_audit = load_json(binding_dir / "good-audit-summary.json")
    assert_true(good_audit.get("runner_result_binding_checked") == 1, "Runner evidence should be bound to one matching results step.")

    write_json(binding_dir / "missing-step-results.json", {**good_results, "scenarios": []})
    missing_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "missing-step-results.json"),
            "--summary",
            str(binding_dir / "missing-step-audit-summary.json"),
        ],
        cwd=binding_dir,
        text=True,
        capture_output=True,
    )
    assert_true(missing_proc.returncode != 0, "Runner evidence without a matching results step must fail audit.")
    missing_audit = load_json(binding_dir / "missing-step-audit-summary.json")
    missing_errors = "\n".join(missing_audit.get("errors", []))
    assert_true("Runner-generated evidence E-runner has no matching results.json step" in missing_errors, "Audit should name the missing runner step binding.")

    write_json(binding_dir / "failed-step-results.json", {**good_results, "scenarios": [{**good_results["scenarios"][0], "steps": [{**good_results["scenarios"][0]["steps"][0], "status": "failed", "error": "Ready text missing"}]}]})
    status_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "failed-step-results.json"),
            "--summary",
            str(binding_dir / "status-mismatch-audit-summary.json"),
        ],
        cwd=binding_dir,
        text=True,
        capture_output=True,
    )
    assert_true(status_proc.returncode != 0, "Runner evidence status must match the bound results step status.")
    status_audit = load_json(binding_dir / "status-mismatch-audit-summary.json")
    status_errors = "\n".join(status_audit.get("errors", []))
    assert_true("does not match results.json step status" in status_errors, "Audit should name runner evidence status mismatches.")

    api_field_dir = tmp_path / "runner-result-field-binding"
    (api_field_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (api_field_dir / "evidence" / "api-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    api_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api",
                "source": "fixture",
                "text": "API evidence copied from runner results must not be hand-mutated.",
                "test_ids": ["T-api"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": "API response is 200 and ok=true.",
                "status": "Untested",
            }
        ],
    }
    api_ledger = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api",
                "source": "fixture",
                "text": api_matrix["requirements"][0]["text"],
                "test_ids": ["T-api"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "tests": [
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": api_matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "evidence": [
            {
                "id": "E-api",
                "type": "api_response",
                "current_run": True,
                "generated_by": "ledger_from_probe.py",
                "scenario_id": "api",
                "step_id": "T-api",
                "action": "api",
                "status": "passed",
                "test_ids": ["T-api"],
                "requirement_ids": ["R-api"],
                "proves": "API returned ok=true.",
                "url": "/api/v1/fixture",
                "body_path": "evidence/api-response.json",
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            }
        ],
    }
    api_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(api_field_dir),
        "scenarios": [
            {
                "id": "api",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "api",
                        "stepId": "T-api",
                        "testIds": ["T-api"],
                        "requirementIds": ["R-api"],
                        "action": "api",
                        "status": "passed",
                        "evidenceType": "api_response",
                        "url": "/api/v1/fixture",
                        "bodyPath": "evidence/api-response.json",
                        "statusCode": 204,
                        "checkedJson": {"ok": False},
                        "proves": "API runner step intentionally disagrees with ledger evidence.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    write_json(api_field_dir / "test-matrix.json", api_matrix)
    write_json(api_field_dir / "evidence-ledger.json", api_ledger)
    write_json(api_field_dir / "results.json", api_results)
    field_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(api_field_dir / "test-matrix.json"),
            "--ledger",
            str(api_field_dir / "evidence-ledger.json"),
            "--results",
            str(api_field_dir / "results.json"),
            "--summary",
            str(api_field_dir / "field-mismatch-audit-summary.json"),
        ],
        cwd=api_field_dir,
        text=True,
        capture_output=True,
    )
    assert_true(field_proc.returncode != 0, "Runner evidence fields must match the bound results step fields.")
    field_audit = load_json(api_field_dir / "field-mismatch-audit-summary.json")
    field_errors = "\n".join(field_audit.get("errors", []))
    assert_true("does not match bound results.json step fields" in field_errors, "Audit should name runner evidence field mismatches.")

    deleted_field_dir = tmp_path / "runner-result-deleted-field-binding"
    (deleted_field_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (deleted_field_dir / "evidence" / "api-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    deleted_field_ledger = json.loads(json.dumps(api_ledger))
    deleted_evidence = deleted_field_ledger["evidence"][0]
    deleted_evidence.pop("body_path", None)
    deleted_evidence.pop("status_code", None)
    deleted_evidence.pop("checked_json", None)
    deleted_evidence["path"] = "evidence/api-response.json"
    deleted_field_results = json.loads(json.dumps(api_results))
    deleted_step = deleted_field_results["scenarios"][0]["steps"][0]
    deleted_step["statusCode"] = 200
    deleted_step["checkedJson"] = {"ok": True}
    deleted_step["proves"] = "API returned ok=true."
    write_json(deleted_field_dir / "test-matrix.json", api_matrix)
    write_json(deleted_field_dir / "evidence-ledger.json", deleted_field_ledger)
    write_json(deleted_field_dir / "results.json", deleted_field_results)
    deleted_field_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(deleted_field_dir / "test-matrix.json"),
            "--ledger",
            str(deleted_field_dir / "evidence-ledger.json"),
            "--results",
            str(deleted_field_dir / "results.json"),
            "--summary",
            str(deleted_field_dir / "deleted-field-audit-summary.json"),
        ],
        cwd=deleted_field_dir,
        text=True,
        capture_output=True,
    )
    assert_true(deleted_field_proc.returncode != 0, "Runner evidence must preserve copied fields from the bound results step.")
    deleted_field_audit = load_json(deleted_field_dir / "deleted-field-audit-summary.json")
    deleted_field_errors = "\n".join(deleted_field_audit.get("errors", []))
    assert_true("status_code is missing from ledger" in deleted_field_errors, "Audit should reject removed runner status_code fields.")
    assert_true("checked_json is missing from ledger" in deleted_field_errors, "Audit should reject removed runner checked_json fields.")

    verdict_dir = tmp_path / "runner-result-binding-verdict"
    write_json(verdict_dir / "test-matrix.json", matrix)
    write_json(verdict_dir / "evidence-ledger.json", ledger_for())
    write_json(verdict_dir / "results.json", {**good_results, "scenarios": []})
    write_synthetic_passing_audit_summary(verdict_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_dir / "audit-summary.json"),
            "--results",
            str(verdict_dir / "results.json"),
            "--out",
            str(verdict_dir / "qa-verdict.json"),
        ],
        cwd=verdict_dir,
    )
    verdict = load_json(verdict_dir / "qa-verdict.json")
    codes = {reason.get("code") for reason in verdict.get("reasons", [])}
    assert_true(verdict.get("can_claim_pass") is False, "verdict should reject unbound runner evidence even if audit input claims passed.")
    assert_true("runner_evidence_unbound" in codes, "verdict should independently flag unbound runner evidence.")

    verdict_field_dir = tmp_path / "runner-result-field-binding-verdict"
    write_json(verdict_field_dir / "test-matrix.json", api_matrix)
    write_json(verdict_field_dir / "evidence-ledger.json", api_ledger)
    write_json(verdict_field_dir / "results.json", api_results)
    write_synthetic_passing_audit_summary(verdict_field_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_field_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_field_dir / "audit-summary.json"),
            "--results",
            str(verdict_field_dir / "results.json"),
            "--out",
            str(verdict_field_dir / "qa-verdict.json"),
        ],
        cwd=verdict_field_dir,
    )
    field_verdict = load_json(verdict_field_dir / "qa-verdict.json")
    field_codes = {reason.get("code") for reason in field_verdict.get("reasons", [])}
    assert_true(field_verdict.get("can_claim_pass") is False, "verdict should reject runner evidence whose copied fields disagree with results.")
    assert_true("runner_evidence_unbound" in field_codes, "verdict should independently flag runner evidence field mismatches.")

    verdict_deleted_field_dir = tmp_path / "runner-result-deleted-field-binding-verdict"
    write_json(verdict_deleted_field_dir / "test-matrix.json", api_matrix)
    write_json(verdict_deleted_field_dir / "evidence-ledger.json", deleted_field_ledger)
    write_json(verdict_deleted_field_dir / "results.json", deleted_field_results)
    write_synthetic_passing_audit_summary(verdict_deleted_field_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_deleted_field_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_deleted_field_dir / "audit-summary.json"),
            "--results",
            str(verdict_deleted_field_dir / "results.json"),
            "--out",
            str(verdict_deleted_field_dir / "qa-verdict.json"),
        ],
        cwd=verdict_deleted_field_dir,
    )
    deleted_field_verdict = load_json(verdict_deleted_field_dir / "qa-verdict.json")
    deleted_field_codes = {reason.get("code") for reason in deleted_field_verdict.get("reasons", [])}
    assert_true(deleted_field_verdict.get("can_claim_pass") is False, "verdict should reject runner evidence with deleted copied fields.")
    assert_true("runner_evidence_unbound" in deleted_field_codes, "verdict should independently flag deleted runner evidence fields.")


def run_requirement_status_consistency_fixture(script_dir: Path, tmp_path: Path) -> None:
    status_dir = tmp_path / "requirement-status-consistency"
    status_dir.mkdir(parents=True, exist_ok=True)
    (status_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (status_dir / "evidence" / "status-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-status",
                "source": "fixture",
                "text": "A requirement cannot pass while one mapped test is still failed.",
                "test_ids": ["T-pass", "T-second"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-pass",
                "requirement_ids": ["R-status"],
                "type": "api",
                "expected": "First API proof returns ok=true.",
                "status": "Untested",
            },
            {
                "id": "T-second",
                "requirement_ids": ["R-status"],
                "type": "api",
                "expected": "Second API proof returns ok=true.",
                "status": "Untested",
            },
        ],
    }
    write_json(status_dir / "test-matrix.json", matrix)

    def evidence_item(evidence_id: str, test_id: str) -> dict[str, Any]:
        return {
            "id": evidence_id,
            "type": "api_response",
            "url": f"/api/{test_id}",
            "body_path": "evidence/status-response.json",
            "generated_by": "ledger_from_probe.py",
            "current_run": True,
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "test_ids": [test_id],
            "requirement_ids": ["R-status"],
            "proves": f"{test_id} returned ok=true.",
        }

    def ledger_for(second_status: str) -> dict[str, Any]:
        second_passed = second_status == "Passed"
        second_test = {
            "id": "T-second",
            "requirement_ids": ["R-status"],
            "type": "api",
            "expected": matrix["tests"][1]["expected"],
            "status": second_status,
            "evidence_ids": ["E-second"] if second_passed else [],
        }
        if not second_passed:
            second_test["notes"] = "Second proof failed in the current run."
        evidence = [evidence_item("E-pass", "T-pass")]
        if second_passed:
            evidence.append(evidence_item("E-second", "T-second"))
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-status",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-pass", "T-second"],
                    "status": "Passed",
                    "evidence_ids": ["E-pass"] + (["E-second"] if second_passed else []),
                }
            ],
            "tests": [
                {
                    "id": "T-pass",
                    "requirement_ids": ["R-status"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-pass"],
                },
                second_test,
            ],
            "evidence": evidence,
        }

    write_json(status_dir / "bad-ledger.json", ledger_for("Failed"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(status_dir / "test-matrix.json"),
            "--ledger",
            str(status_dir / "bad-ledger.json"),
            "--summary",
            str(status_dir / "bad-audit-summary.json"),
        ],
        cwd=str(status_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "A Passed requirement with a failed mapped test must fail audit.")
    bad_audit = load_json(status_dir / "bad-audit-summary.json")
    assert_true("Requirement R-status is Passed but mapped test T-second has status 'Failed'." in "\n".join(bad_audit.get("errors", [])), "Status consistency audit should name the contradictory mapped test.")
    assert_true(bad_audit.get("requirement_status_consistency_checked") == 2, "Status consistency audit should count mapped tests on passed requirements.")

    write_json(status_dir / "good-ledger.json", ledger_for("Passed"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(status_dir / "test-matrix.json"),
            "--ledger",
            str(status_dir / "good-ledger.json"),
            "--summary",
            str(status_dir / "good-audit-summary.json"),
        ],
        cwd=status_dir,
    )
    good_audit = load_json(status_dir / "good-audit-summary.json")
    assert_true(good_audit.get("requirement_status_consistency_checked") == 2, "Passing mapped tests should satisfy requirement status consistency.")


def run_verdict_artifact_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    binding_root = tmp_path / "verdict-artifact-binding"
    binding_root.mkdir(parents=True, exist_ok=True)

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-binding",
                "source": "fixture",
                "text": "Final verdict must be generated from the same audited ledger and results.",
                "test_ids": ["T-binding"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-binding",
                "requirement_ids": ["R-binding"],
                "type": "api",
                "expected": "API response returns ok=true.",
                "status": "Untested",
            }
        ],
    }
    good_ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-binding",
                "source": "fixture",
                "text": matrix["requirements"][0]["text"],
                "test_ids": ["T-binding"],
                "status": "Passed",
                "evidence_ids": ["E-binding"],
            }
        ],
        "tests": [
            {
                "id": "T-binding",
                "requirement_ids": ["R-binding"],
                "type": "api",
                "expected": matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-binding"],
            }
        ],
        "evidence": [
            {
                "id": "E-binding",
                "type": "api_response",
                "url": "/api/v1/binding",
                "body_path": "evidence/binding-response.json",
                "generated_by": "ledger_from_probe.py",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "test_ids": ["T-binding"],
                "requirement_ids": ["R-binding"],
                "proves": "The API response returned ok=true.",
            }
        ],
    }
    good_results = {
        "schemaVersion": 2,
        "status": "passed",
        "startedAt": "2026-06-15T00:00:00+00:00",
        "scenarios": [
            {
                "id": "binding",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "binding",
                        "stepId": "T-binding",
                        "testIds": ["T-binding"],
                        "requirementIds": ["R-binding"],
                        "action": "api",
                        "status": "passed",
                        "evidenceType": "api_response",
                        "statusCode": 200,
                        "bodyPath": "evidence/binding-response.json",
                        "checkedJson": {"ok": True},
                        "proves": "The API response returned ok=true.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    defects = {"summary": {"finding_count": 0, "severity_counts": {}}}

    def prepare_case(case_dir: Path) -> None:
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence" / "binding-response.json").write_text('{"ok":true}\n', encoding="utf-8")
        write_json(case_dir / "test-matrix.json", matrix)
        write_json(case_dir / "evidence-ledger.json", good_ledger)
        write_json(case_dir / "results.json", {**good_results, "artifactDir": str(case_dir)})
        write_json(case_dir / "defects.json", defects)
        run_cmd(
            [
                sys.executable,
                str(script_dir / "audit_evidence.py"),
                "--matrix",
                str(case_dir / "test-matrix.json"),
                "--results",
                str(case_dir / "results.json"),
                "--ledger",
                str(case_dir / "evidence-ledger.json"),
                "--summary",
                str(case_dir / "audit-summary.json"),
            ],
            cwd=case_dir,
        )

    def generate_case_verdict(
        case_dir: Path,
        name: str,
        fail_on_not_pass: bool = False,
        include_results: bool = True,
        include_defects: bool = True,
        include_requirement_coverage: bool = False,
    ) -> dict[str, Any]:
        cmd = [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(case_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(case_dir / "audit-summary.json"),
            "--out",
            str(case_dir / f"{name}-verdict.json"),
        ]
        if include_results:
            cmd.extend(["--results", str(case_dir / "results.json")])
        if include_defects:
            cmd.extend(["--defects", str(case_dir / "defects.json")])
        if include_requirement_coverage:
            cmd.extend(["--requirement-coverage", str(case_dir / "requirement-coverage.json")])
        if fail_on_not_pass:
            cmd.append("--fail-on-not-pass")
        run_cmd(cmd, cwd=case_dir)
        return load_json(case_dir / f"{name}-verdict.json")

    good_dir = binding_root / "good"
    prepare_case(good_dir)
    good_verdict = generate_case_verdict(good_dir, "good", fail_on_not_pass=True)
    assert_true(good_verdict.get("can_claim_pass") is True, "Matching audit, ledger, and results should allow a clean pass verdict.")
    assert_true(good_verdict.get("gates", {}).get("audit_artifacts_bound") is True, "Verdict should expose a passing artifact binding gate.")

    inconsistent_defects_dir = binding_root / "inconsistent-defects"
    prepare_case(inconsistent_defects_dir)
    write_json(
        inconsistent_defects_dir / "defects.json",
        {
            "summary": {"finding_count": 0, "severity_counts": {}},
            "findings": [{"id": "D-hidden", "severity": "P1", "title": "Hidden defect despite zero summary count."}],
        },
    )
    inconsistent_defects_verdict = generate_case_verdict(inconsistent_defects_dir, "inconsistent-defects")
    inconsistent_defects_codes = {reason.get("code") for reason in inconsistent_defects_verdict.get("reasons", [])}
    assert_true(inconsistent_defects_verdict.get("can_claim_pass") is False, "Defect findings must block pass even when summary.finding_count is stale or wrong.")
    assert_true("defects_present" in inconsistent_defects_codes, "Verdict should treat defects.findings as authoritative evidence of defects.")
    assert_true("defects_summary_mismatch" in inconsistent_defects_codes, "Verdict should expose mismatched defects summary counts.")
    assert_true(inconsistent_defects_verdict.get("gates", {}).get("defect_free") is False, "Mismatched defect findings should mark defect_free=false.")

    cross_run_defects_dir = binding_root / "cross-run-defects"
    prepare_case(cross_run_defects_dir)
    clean_artifact_dir = binding_root / "clean-artifact-source"
    clean_artifact_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        cross_run_defects_dir / "defects.json",
        {"summary": {"finding_count": 1, "severity_counts": {"P1": 1}}, "findings": [{"id": "D-current", "severity": "P1"}]},
    )
    write_json(clean_artifact_dir / "defects.json", defects)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(cross_run_defects_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(cross_run_defects_dir / "audit-summary.json"),
            "--results",
            str(cross_run_defects_dir / "results.json"),
            "--defects",
            str(clean_artifact_dir / "defects.json"),
            "--out",
            str(cross_run_defects_dir / "cross-run-defects-verdict.json"),
        ],
        cwd=cross_run_defects_dir,
    )
    cross_run_defects_verdict = load_json(cross_run_defects_dir / "cross-run-defects-verdict.json")
    cross_run_defects_codes = {reason.get("code") for reason in cross_run_defects_verdict.get("reasons", [])}
    assert_true(cross_run_defects_verdict.get("can_claim_pass") is False, "A clean defects artifact from another run must not hide current sibling defects.json.")
    assert_true("defects_sibling_path_mismatch" in cross_run_defects_codes, "Verdict should report cross-run defects artifact path mismatch.")

    artifact_dir_mismatch_dir = binding_root / "results-artifact-dir-mismatch"
    prepare_case(artifact_dir_mismatch_dir)
    external_artifact_dir = binding_root / "external-results-artifacts"
    external_artifact_dir.mkdir(parents=True, exist_ok=True)
    changed_results = json.loads(json.dumps(good_results))
    changed_results["artifactDir"] = str(external_artifact_dir)
    write_json(artifact_dir_mismatch_dir / "results.json", changed_results)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(artifact_dir_mismatch_dir / "test-matrix.json"),
            "--results",
            str(artifact_dir_mismatch_dir / "results.json"),
            "--ledger",
            str(artifact_dir_mismatch_dir / "evidence-ledger.json"),
            "--summary",
            str(artifact_dir_mismatch_dir / "audit-summary.json"),
        ],
        cwd=artifact_dir_mismatch_dir,
    )
    artifact_dir_mismatch_verdict = generate_case_verdict(artifact_dir_mismatch_dir, "results-artifact-dir-mismatch")
    artifact_dir_mismatch_codes = {reason.get("code") for reason in artifact_dir_mismatch_verdict.get("reasons", [])}
    assert_true(artifact_dir_mismatch_verdict.get("can_claim_pass") is False, "A results.json artifactDir from another run must block final pass.")
    assert_true("results_artifact_dir_mismatch" in artifact_dir_mismatch_codes, "Verdict should report artifactDir mismatch against the current run directory.")
    assert_true("results_artifact_dir_not_results_parent" in artifact_dir_mismatch_codes, "Verdict should report artifactDir mismatch against results.json parent.")

    artifact_changed_dir = binding_root / "evidence-artifact-changed"
    prepare_case(artifact_changed_dir)
    (artifact_changed_dir / "evidence" / "binding-response.json").write_text('{"ok":false}\n', encoding="utf-8")
    artifact_changed_verdict = generate_case_verdict(artifact_changed_dir, "evidence-artifact-changed")
    artifact_changed_codes = {reason.get("code") for reason in artifact_changed_verdict.get("reasons", [])}
    assert_true(artifact_changed_verdict.get("can_claim_pass") is False, "An evidence artifact changed after audit must block final pass.")
    assert_true("audit_evidence_artifact_hash_mismatch" in artifact_changed_codes, "Verdict should report evidence artifact hash mismatch after audit.")

    malformed_optional_dir = binding_root / "malformed-optional-input"
    prepare_case(malformed_optional_dir)
    (malformed_optional_dir / "adapter-context.json").write_text("{not-json", encoding="utf-8")
    malformed_cmd = [
        sys.executable,
        str(script_dir / "generate_verdict.py"),
        "--ledger",
        str(malformed_optional_dir / "evidence-ledger.json"),
        "--audit-summary",
        str(malformed_optional_dir / "audit-summary.json"),
        "--results",
        str(malformed_optional_dir / "results.json"),
        "--defects",
        str(malformed_optional_dir / "defects.json"),
        "--adapter-context",
        str(malformed_optional_dir / "adapter-context.json"),
        "--require-environment-boundary",
        "--out",
        str(malformed_optional_dir / "malformed-optional-verdict.json"),
        "--fail-on-not-pass",
    ]
    malformed_proc = subprocess.run(malformed_cmd, cwd=str(malformed_optional_dir), text=True, capture_output=True)
    assert_true(malformed_proc.returncode != 0, "fail-on-not-pass should exit non-zero for unreadable optional verdict inputs.")
    assert_true("Traceback" not in malformed_proc.stderr, "generate_verdict should not crash on malformed optional artifact JSON.")
    malformed_optional_verdict = load_json(malformed_optional_dir / "malformed-optional-verdict.json")
    malformed_optional_codes = {reason.get("code") for reason in malformed_optional_verdict.get("reasons", [])}
    malformed_input_names = {item.get("name") for item in malformed_optional_verdict.get("input_artifact_errors", [])}
    assert_true(malformed_optional_verdict.get("can_claim_pass") is False, "Unreadable optional verdict inputs must block pass claims.")
    assert_true("input_artifact_unreadable" in malformed_optional_codes, "Verdict should report unreadable input artifacts instead of crashing.")
    assert_true("adapter_context" in malformed_input_names, "Verdict should name the unreadable adapter context input.")

    unreadable_results_dir = binding_root / "unreadable-results-input"
    prepare_case(unreadable_results_dir)
    (unreadable_results_dir / "results.json").unlink()
    (unreadable_results_dir / "results.json").mkdir()
    unreadable_results_verdict = generate_case_verdict(unreadable_results_dir, "unreadable-results")
    unreadable_results_codes = {reason.get("code") for reason in unreadable_results_verdict.get("reasons", [])}
    unreadable_input_names = {item.get("name") for item in unreadable_results_verdict.get("input_artifact_errors", [])}
    assert_true(unreadable_results_verdict.get("can_claim_pass") is False, "Directory-shaped results input must block pass claims.")
    assert_true("input_artifact_unreadable" in unreadable_results_codes, "Verdict should report directory-shaped results as unreadable input.")
    assert_true("audit_results_unreadable" in unreadable_results_codes, "Verdict should report that audit-bound results cannot be hash-verified.")
    assert_true("results" in unreadable_input_names, "Verdict should name the unreadable results input.")

    unbound_matrix_dir = binding_root / "unbound-matrix"
    unbound_matrix_dir.mkdir(parents=True, exist_ok=True)
    (unbound_matrix_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (unbound_matrix_dir / "evidence" / "binding-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(unbound_matrix_dir / "test-matrix.json", matrix)
    write_json(unbound_matrix_dir / "evidence-ledger.json", good_ledger)
    write_json(
        unbound_matrix_dir / "results.json",
        {**good_results, "artifactDir": str(unbound_matrix_dir)},
    )
    write_json(unbound_matrix_dir / "defects.json", defects)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--results",
            str(unbound_matrix_dir / "results.json"),
            "--ledger",
            str(unbound_matrix_dir / "evidence-ledger.json"),
            "--summary",
            str(unbound_matrix_dir / "audit-summary.json"),
        ],
        cwd=unbound_matrix_dir,
    )
    unbound_matrix_verdict = generate_case_verdict(unbound_matrix_dir, "unbound-matrix")
    unbound_matrix_codes = {reason.get("code") for reason in unbound_matrix_verdict.get("reasons", [])}
    assert_true(unbound_matrix_verdict.get("can_claim_pass") is False, "A verdict whose audit omitted test-matrix.json must not claim pass.")
    assert_true("audit_matrix_unbound" in unbound_matrix_codes, "Verdict should report unbound matrix when audit omitted --matrix.")

    omitted_results_verdict = generate_case_verdict(good_dir, "omitted-results", include_results=False)
    omitted_results_codes = {reason.get("code") for reason in omitted_results_verdict.get("reasons", [])}
    assert_true(omitted_results_verdict.get("can_claim_pass") is False, "A verdict that omits audit-bound results.json must not claim pass.")
    assert_true("audit_results_omitted" in omitted_results_codes, "Verdict should report omitted results when audit was generated with results.json.")

    omitted_defects_dir = binding_root / "omitted-defects"
    prepare_case(omitted_defects_dir)
    write_json(
        omitted_defects_dir / "defects.json",
        {"summary": {"finding_count": 1, "severity_counts": {"P1": 1}}, "findings": [{"id": "D-hidden", "severity": "P1"}]},
    )
    omitted_defects_verdict = generate_case_verdict(omitted_defects_dir, "omitted-defects", include_defects=False)
    omitted_defects_codes = {reason.get("code") for reason in omitted_defects_verdict.get("reasons", [])}
    assert_true(omitted_defects_verdict.get("can_claim_pass") is False, "A verdict that omits sibling defects.json must not claim pass.")
    assert_true("defects_omitted" in omitted_defects_codes, "Verdict should report omitted defects when defects.json exists beside the ledger.")

    omitted_coverage_dir = binding_root / "omitted-coverage"
    prepare_case(omitted_coverage_dir)
    write_json(
        omitted_coverage_dir / "requirement-coverage.json",
        {
            "passed": False,
            "uncovered_count": 1,
            "coverage": [{"id": "SRC-hidden", "source": "fixture", "covered": False}],
        },
    )
    omitted_coverage_verdict = generate_case_verdict(omitted_coverage_dir, "omitted-coverage")
    omitted_coverage_codes = {reason.get("code") for reason in omitted_coverage_verdict.get("reasons", [])}
    assert_true(omitted_coverage_verdict.get("can_claim_pass") is False, "A verdict that omits sibling requirement-coverage.json must not claim pass.")
    assert_true("requirement_coverage_omitted" in omitted_coverage_codes, "Verdict should report omitted requirement coverage when requirement-coverage.json exists beside the ledger.")

    omitted_setup_adapter_dir = binding_root / "omitted-setup-adapter"
    prepare_case(omitted_setup_adapter_dir)
    write_json(
        omitted_setup_adapter_dir / "service-preflight.json",
        {"blockers": [{"service": "api", "reason": "synthetic service unavailable"}]},
    )
    write_json(
        omitted_setup_adapter_dir / "service-runtime.json",
        {
            "mode": "start",
            "summary": {"planned_count": 1, "ready_count": 0, "failed_count": 1},
            "services": [{"service": "api", "status": "failed"}],
        },
    )
    write_json(
        omitted_setup_adapter_dir / "adapter-probes.json",
        {"blocked": [{"layer": "stream", "reason": "synthetic stream endpoint missing"}]},
    )
    write_json(
        omitted_setup_adapter_dir / "adapter-context.json",
        {"environment_boundary": {"runtime_mode": "unconfirmed", "data_boundary_status": "unconfirmed"}},
    )
    omitted_setup_adapter_verdict = generate_case_verdict(omitted_setup_adapter_dir, "omitted-setup-adapter")
    omitted_setup_adapter_codes = {reason.get("code") for reason in omitted_setup_adapter_verdict.get("reasons", [])}
    expected_setup_adapter_codes = {
        "service_preflight_omitted",
        "service_runtime_omitted",
        "adapter_probes_omitted",
        "adapter_context_omitted",
    }
    assert_true(omitted_setup_adapter_verdict.get("can_claim_pass") is False, "A verdict that omits sibling setup/adapter artifacts must not claim pass.")
    assert_true(expected_setup_adapter_codes <= omitted_setup_adapter_codes, "Verdict should report every omitted setup/adapter sibling artifact.")

    omitted_cycle_error_dir = binding_root / "omitted-cycle-error"
    prepare_case(omitted_cycle_error_dir)
    write_json(
        omitted_cycle_error_dir / "qa-cycle-error.json",
        {
            "schema_version": 1,
            "code": "cycle_helper_failed",
            "phase": "generate_report",
            "message": "Synthetic report generation failure after audit.",
        },
    )
    omitted_cycle_error_verdict = generate_case_verdict(omitted_cycle_error_dir, "omitted-cycle-error")
    omitted_cycle_error_codes = {reason.get("code") for reason in omitted_cycle_error_verdict.get("reasons", [])}
    assert_true(omitted_cycle_error_verdict.get("can_claim_pass") is False, "A verdict that omits sibling qa-cycle-error.json must not claim pass.")
    assert_true("cycle_error_omitted" in omitted_cycle_error_codes, "Verdict should report omitted cycle error when qa-cycle-error.json exists beside the ledger.")
    assert_true(omitted_cycle_error_verdict.get("gates", {}).get("cycle_completed") is False, "Omitted cycle errors should mark the cycle incomplete.")

    matrix_changed_dir = binding_root / "matrix-changed"
    prepare_case(matrix_changed_dir)
    changed_matrix = json.loads(json.dumps(matrix))
    changed_matrix["requirements"].append(
        {
            "id": "R-new-after-audit",
            "source": "fixture",
            "text": "Synthetic requirement added after audit.",
            "test_ids": ["T-new-after-audit"],
            "status": "Untested",
        }
    )
    changed_matrix["tests"].append(
        {
            "id": "T-new-after-audit",
            "requirement_ids": ["R-new-after-audit"],
            "type": "api",
            "expected": "Synthetic test added after audit.",
            "status": "Untested",
        }
    )
    write_json(matrix_changed_dir / "test-matrix.json", changed_matrix)
    matrix_changed_verdict = generate_case_verdict(matrix_changed_dir, "matrix-changed")
    matrix_changed_codes = {reason.get("code") for reason in matrix_changed_verdict.get("reasons", [])}
    assert_true(matrix_changed_verdict.get("can_claim_pass") is False, "A matrix changed after audit must block final pass.")
    assert_true("audit_matrix_hash_mismatch" in matrix_changed_codes, "Verdict should report matrix hash mismatch after audit.")

    ledger_changed_dir = binding_root / "ledger-changed"
    prepare_case(ledger_changed_dir)
    changed_ledger = json.loads(json.dumps(good_ledger))
    changed_ledger["requirements"][0]["status"] = "Failed"
    changed_ledger["requirements"][0]["notes"] = "Synthetic contradiction after audit."
    changed_ledger["tests"][0]["status"] = "Failed"
    changed_ledger["tests"][0]["notes"] = "Synthetic contradiction after audit."
    write_json(ledger_changed_dir / "evidence-ledger.json", changed_ledger)
    ledger_changed_verdict = generate_case_verdict(ledger_changed_dir, "ledger-changed")
    ledger_changed_codes = {reason.get("code") for reason in ledger_changed_verdict.get("reasons", [])}
    assert_true(ledger_changed_verdict.get("can_claim_pass") is False, "A ledger changed after audit must block final pass.")
    assert_true("audit_ledger_hash_mismatch" in ledger_changed_codes, "Verdict should report ledger hash mismatch after audit.")
    assert_true("audit_status_counts_mismatch" in ledger_changed_codes, "Verdict should report status count mismatch after ledger mutation.")
    assert_true("requirement_failed" in ledger_changed_codes, "Verdict should count requirement status from the current ledger, not stale audit summary.")

    results_changed_dir = binding_root / "results-changed"
    prepare_case(results_changed_dir)
    changed_results = json.loads(json.dumps(good_results))
    changed_results["console"] = [{"type": "error", "text": "synthetic runtime error after audit"}]
    write_json(results_changed_dir / "results.json", changed_results)
    results_changed_verdict = generate_case_verdict(results_changed_dir, "results-changed")
    results_changed_codes = {reason.get("code") for reason in results_changed_verdict.get("reasons", [])}
    assert_true(results_changed_verdict.get("can_claim_pass") is False, "Results changed after audit must block final pass.")
    assert_true("audit_results_hash_mismatch" in results_changed_codes, "Verdict should report results hash mismatch after audit.")
    assert_true("undispositioned_console_errors" in results_changed_codes, "Verdict should still inspect current results runtime errors.")


def run_report_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    report_dir = tmp_path / "report-input-errors"
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        report_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(report_dir),
            "scenarios": [
                {
                    "id": "report-fixture",
                    "title": "Report fixture",
                    "steps": [],
                }
            ],
        },
    )
    good_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(report_dir),
        "startedAt": "2026-06-15T00:00:00+00:00",
        "finishedAt": "2026-06-15T00:00:01+00:00",
        "scenarios": [{"id": "report-fixture", "title": "Report fixture", "status": "passed", "steps": []}],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }

    required_bad_dir = report_dir / "required-results"
    required_bad_dir.mkdir(parents=True, exist_ok=True)
    write_json(required_bad_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    (required_bad_dir / "results.json").write_text("{not-json", encoding="utf-8")
    required_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(required_bad_dir / "test-plan.json"),
            "--results",
            str(required_bad_dir / "results.json"),
            "--out",
            str(required_bad_dir / "report.md"),
        ],
        cwd=required_bad_dir,
        text=True,
        capture_output=True,
    )
    assert_true(required_proc.returncode != 0, "Report generation should exit non-zero when required results.json is unreadable.")
    assert_true("Traceback" not in required_proc.stderr, "Report generation should not expose unreadable required inputs as a traceback.")
    required_report = (required_bad_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Report Input Errors" in required_report, "Partial report should include an explicit input error section.")
    assert_true("results" in required_report and "invalid_json" in required_report, "Partial report should name unreadable required results input.")
    assert_true("Report completeness: PARTIAL" in required_report, "Partial report should block final pass/fail claims.")

    optional_bad_dir = report_dir / "optional-verdict"
    optional_bad_dir.mkdir(parents=True, exist_ok=True)
    write_json(optional_bad_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    write_json(optional_bad_dir / "results.json", {**good_results, "artifactDir": str(optional_bad_dir)})
    (optional_bad_dir / "qa-verdict.json").write_text("{not-json", encoding="utf-8")
    optional_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(optional_bad_dir / "test-plan.json"),
            "--results",
            str(optional_bad_dir / "results.json"),
            "--verdict",
            str(optional_bad_dir / "qa-verdict.json"),
            "--out",
            str(optional_bad_dir / "report.md"),
        ],
        cwd=optional_bad_dir,
        text=True,
        capture_output=True,
    )
    assert_true(optional_proc.returncode != 0, "Report generation should exit non-zero when an explicit optional verdict input is unreadable.")
    assert_true("Traceback" not in optional_proc.stderr, "Report generation should not expose unreadable optional inputs as a traceback.")
    optional_report = (optional_bad_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Report Input Errors" in optional_report, "Report should keep optional input errors visible.")
    assert_true("verdict" in optional_report and "invalid_json" in optional_report, "Report should name unreadable optional verdict input.")
    assert_true("Probe result: PASS" in optional_report, "Readable plan/results content should still render in a partial report.")

    verdict_blocked_dir = report_dir / "verdict-blocked-pass-claim"
    verdict_blocked_dir.mkdir(parents=True, exist_ok=True)
    write_json(verdict_blocked_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    write_json(verdict_blocked_dir / "results.json", {**good_results, "artifactDir": str(verdict_blocked_dir)})
    write_json(
        verdict_blocked_dir / "evidence-ledger.json",
        {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-report",
                    "source": "fixture",
                    "text": "Report should not claim final pass when verdict blocks pass.",
                    "test_ids": ["T-report"],
                    "status": "Passed",
                    "evidence_ids": ["E-report"],
                }
            ],
            "tests": [
                {
                    "id": "T-report",
                    "requirement_ids": ["R-report"],
                    "type": "api",
                    "expected": "The API fixture returns ok=true.",
                    "status": "Passed",
                    "evidence_ids": ["E-report"],
                }
            ],
            "evidence": [
                {
                    "id": "E-report",
                    "type": "api_response",
                    "current_run": True,
                    "url": "/api/v1/report-fixture",
                    "status_code": 200,
                    "checked_json": {"ok": True},
                    "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                    "proves": "The API fixture returned ok=true.",
                }
            ],
        },
    )
    write_json(
        verdict_blocked_dir / "audit-summary.json",
        {
            "passed": True,
            "requirement_count": 1,
            "test_count": 1,
            "evidence_count": 1,
            "errors": [],
            "warnings": [],
        },
    )
    write_json(
        verdict_blocked_dir / "qa-verdict.json",
        {
            "verdict": "inconclusive",
            "can_claim_pass": False,
            "statement": "Do not claim pass: environment boundary is incomplete.",
            "gates": {"environment_boundary_confirmed": False},
            "reasons": [
                {
                    "code": "data_boundary_unconfirmed",
                    "category": "environment",
                    "severity": "gap",
                    "message": "Data boundary is unconfirmed.",
                    "refs": ["adapter-context.json"],
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(verdict_blocked_dir / "test-plan.json"),
            "--results",
            str(verdict_blocked_dir / "results.json"),
            "--ledger",
            str(verdict_blocked_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_blocked_dir / "audit-summary.json"),
            "--verdict",
            str(verdict_blocked_dir / "qa-verdict.json"),
            "--out",
            str(verdict_blocked_dir / "report.md"),
        ],
        cwd=verdict_blocked_dir,
    )
    blocked_report = (verdict_blocked_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: BLOCKED" in blocked_report, "Report should expose verdict-level pass claim blocking.")
    assert_true("Requirement pass/fail: LEDGER PASSED, FINAL PASS BLOCKED by qa-verdict.json." in blocked_report, "Report should separate ledger pass from final pass claim.")
    assert_true("Pass claim guard: DO NOT CLAIM PASS from this report." in blocked_report, "Final verdict section should carry an explicit no-pass guard.")
    assert_true("Requirement pass/fail: PASSED for the audited scope." not in blocked_report, "Report must not use final-pass wording when verdict blocks pass.")

    stale_pass_dir = report_dir / "stale-pass-verdict"
    stale_pass_dir.mkdir(parents=True, exist_ok=True)
    (stale_pass_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (stale_pass_dir / "evidence" / "report-body.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(stale_pass_dir / "test-plan.json", {**load_json(report_dir / "test-plan.json"), "artifactDir": str(stale_pass_dir)})
    write_json(stale_pass_dir / "results.json", {**good_results, "artifactDir": str(stale_pass_dir)})
    write_json(
        stale_pass_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-stale-report",
                    "source": "fixture",
                    "text": "The report must not trust a stale pass verdict.",
                    "test_ids": ["T-stale-report"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-stale-report",
                    "requirement_ids": ["R-stale-report"],
                    "type": "api",
                    "expected": "The API fixture returns ok=true.",
                    "status": "Untested",
                }
            ],
        },
    )
    good_stale_ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-stale-report",
                "source": "fixture",
                "text": "The report must not trust a stale pass verdict.",
                "test_ids": ["T-stale-report"],
                "status": "Passed",
                "evidence_ids": ["E-stale-report"],
            }
        ],
        "tests": [
            {
                "id": "T-stale-report",
                "requirement_ids": ["R-stale-report"],
                "type": "api",
                "expected": "The API fixture returns ok=true.",
                "status": "Passed",
                "evidence_ids": ["E-stale-report"],
            }
        ],
        "evidence": [
            {
                "id": "E-stale-report",
                "type": "api_response",
                "current_run": True,
                "url": "/api/v1/report-fixture",
                "body_path": "evidence/report-body.json",
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "proves": "The API fixture returned ok=true.",
            }
        ],
    }
    write_json(stale_pass_dir / "evidence-ledger.json", good_stale_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(stale_pass_dir / "test-matrix.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--summary",
            str(stale_pass_dir / "audit-summary.json"),
        ],
        cwd=stale_pass_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--out",
            str(stale_pass_dir / "qa-verdict.json"),
            "--fail-on-not-pass",
        ],
        cwd=stale_pass_dir,
    )
    stale_verdict = load_json(stale_pass_dir / "qa-verdict.json")
    assert_true(stale_verdict.get("can_claim_pass") is True, "Stale-report fixture setup should first produce a pass verdict.")
    write_json(
        stale_pass_dir / "defects.json",
        {
            "summary": {"finding_count": 1, "severity_counts": {"P1": 1}},
            "findings": [{"id": "D-late-report", "severity": "P1"}],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "late-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    late_defects_report = (stale_pass_dir / "late-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in late_defects_report, "Report must not allow pass when defects.json appears after a pass verdict.")
    assert_true("Report verdict binding: BLOCKED" in late_defects_report, "Report should expose late defects as a verdict binding blocker.")
    assert_true("defects.json has finding_count=1" in late_defects_report, "Report should name late defect findings that block pass.")

    clean_report_artifact_dir = report_dir / "clean-report-artifact-source"
    clean_report_artifact_dir.mkdir(parents=True, exist_ok=True)
    write_json(clean_report_artifact_dir / "defects.json", {"summary": {"finding_count": 0, "severity_counts": {}}, "findings": []})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--defects",
            str(clean_report_artifact_dir / "defects.json"),
            "--out",
            str(stale_pass_dir / "cross-run-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    cross_run_defects_report = (stale_pass_dir / "cross-run-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in cross_run_defects_report, "Report must not allow pass when an explicit clean defects artifact comes from another run.")
    assert_true("Report verdict binding: BLOCKED" in cross_run_defects_report, "Report should expose cross-run defects artifact path mismatch.")
    assert_true("defects.json exists in the current run" in cross_run_defects_report, "Report should name the current sibling defects artifact that was bypassed.")

    artifactdir_report_dir = report_dir / "results-artifactdir-report"
    external_report_artifact_dir = report_dir / "external-report-artifacts"
    artifactdir_report_dir.mkdir(parents=True, exist_ok=True)
    external_report_artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifactdir_report_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (artifactdir_report_dir / "evidence" / "report-body.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(artifactdir_report_dir / "test-plan.json", {**load_json(report_dir / "test-plan.json"), "artifactDir": str(artifactdir_report_dir)})
    write_json(artifactdir_report_dir / "test-matrix.json", load_json(stale_pass_dir / "test-matrix.json"))
    write_json(artifactdir_report_dir / "evidence-ledger.json", good_stale_ledger)
    write_json(artifactdir_report_dir / "results.json", {**good_results, "artifactDir": str(external_report_artifact_dir)})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(artifactdir_report_dir / "test-matrix.json"),
            "--results",
            str(artifactdir_report_dir / "results.json"),
            "--ledger",
            str(artifactdir_report_dir / "evidence-ledger.json"),
            "--summary",
            str(artifactdir_report_dir / "audit-summary.json"),
        ],
        cwd=artifactdir_report_dir,
    )
    write_json(
        artifactdir_report_dir / "qa-verdict.json",
        {
            "verdict": "passed",
            "can_claim_pass": True,
            "statement": "Synthetic legacy pass verdict before artifactDir guard.",
            "inputs": {
                "ledger": str(artifactdir_report_dir / "evidence-ledger.json"),
                "audit_summary": str(artifactdir_report_dir / "audit-summary.json"),
                "results": str(artifactdir_report_dir / "results.json"),
            },
            "reasons": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(artifactdir_report_dir / "test-plan.json"),
            "--results",
            str(artifactdir_report_dir / "results.json"),
            "--ledger",
            str(artifactdir_report_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(artifactdir_report_dir / "audit-summary.json"),
            "--verdict",
            str(artifactdir_report_dir / "qa-verdict.json"),
            "--out",
            str(artifactdir_report_dir / "report.md"),
        ],
        cwd=artifactdir_report_dir,
    )
    artifactdir_report = (artifactdir_report_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in artifactdir_report, "Report must not allow a pass verdict when results.artifactDir points outside the current run.")
    assert_true("Report verdict binding: BLOCKED" in artifactdir_report, "Report should expose results artifactDir mismatch.")
    assert_true("results.json artifactDir=" in artifactdir_report and "does not match this report's current artifact directory" in artifactdir_report, "Report should name the artifactDir mismatch.")

    write_json(
        stale_pass_dir / "defects.json",
        {
            "summary": {"finding_count": 0, "severity_counts": {}},
            "findings": [{"id": "D-late-hidden", "severity": "P1"}],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "mismatched-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    mismatched_defects_report = (stale_pass_dir / "mismatched-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in mismatched_defects_report, "Report must not allow pass when defects.findings contradict a zero summary count.")
    assert_true("Report verdict binding: BLOCKED" in mismatched_defects_report, "Report should expose mismatched defects as a verdict binding blocker.")
    assert_true("defects.json has finding_count=1" in mismatched_defects_report, "Report should count defect findings even when summary.finding_count is stale.")
    assert_true("summary.finding_count=0 does not match findings length=1" in mismatched_defects_report, "Report should name the defects summary mismatch.")
    assert_true("Defect summary mismatch: summary=0, findings=1" in mismatched_defects_report, "Report summary should surface defects count inconsistency.")
    (stale_pass_dir / "defects.json").unlink()
    write_json(
        stale_pass_dir / "plan-audit-summary.json",
        {
            "passed": False,
            "errors": ["Synthetic weak probe after verdict."],
            "strategy_coverage": {
                "gap_count": 1,
                "gaps": [{"dimension": "persistence", "test_ids": ["T-stale-report"]}],
            },
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "late-plan-audit-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    late_plan_report = (stale_pass_dir / "late-plan-audit-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in late_plan_report, "Report must not allow pass when plan-audit-summary.json fails after a pass verdict.")
    assert_true("Report verdict binding: BLOCKED" in late_plan_report, "Report should expose late plan audit as a verdict binding blocker.")
    assert_true("plan-audit-summary.json is not passed" in late_plan_report, "Report should name failed plan validation that blocks pass.")
    (stale_pass_dir / "plan-audit-summary.json").unlink()
    changed_ledger = json.loads(json.dumps(good_stale_ledger))
    changed_ledger["requirements"][0]["status"] = "Failed"
    changed_ledger["requirements"][0]["notes"] = "Synthetic current contradiction after verdict."
    changed_ledger["tests"][0]["status"] = "Failed"
    changed_ledger["tests"][0]["notes"] = "Synthetic current contradiction after verdict."
    write_json(stale_pass_dir / "evidence-ledger.json", changed_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "report.md"),
        ],
        cwd=stale_pass_dir,
    )
    stale_report = (stale_pass_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in stale_report, "Report must not allow pass when a pass verdict is stale relative to current artifacts.")
    assert_true("Report verdict binding: BLOCKED" in stale_report, "Report should expose stale verdict artifact binding blockers.")
    assert_true("ledger artifact hash differs from audit-summary.json" in stale_report, "Report should name the current ledger/audit hash mismatch.")


def run_next_probe_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    next_dir = tmp_path / "next-probe-input-errors"
    next_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        next_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(next_dir),
            "scenarios": [],
        },
    )
    write_json(
        next_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-next",
                    "source": "fixture",
                    "text": "Next-probe application should report malformed follow-up artifacts.",
                    "test_ids": ["T-next"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-next",
                    "requirement_ids": ["R-next"],
                    "type": "runtime",
                    "expected": "Malformed next-probe input produces a structured handoff.",
                    "status": "Untested",
                }
            ],
        },
    )

    (next_dir / "next-probes.json").write_text("{not-json", encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(next_dir),
            "--out",
            str(next_dir / "next-probe-preview.json"),
        ],
        cwd=next_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "apply_next_probes should exit non-zero when required next-probes.json is unreadable.")
    assert_true("Traceback" not in proc.stderr, "apply_next_probes should not expose unreadable required inputs as a traceback.")
    preview = load_json(next_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors") if isinstance(preview.get("input_artifact_errors"), list) else []
    input_names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    assert_true("next_probes" in input_names, "next-probe preview should name the unreadable next_probes input.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "unreadable next-probe inputs must not apply recommendations.")

    write_json(
        next_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 0},
            "recommendations": [],
        },
    )
    (next_dir / "defects.json").write_text("{not-json", encoding="utf-8")
    optional_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(next_dir),
            "--defects",
            str(next_dir / "defects.json"),
            "--out",
            str(next_dir / "next-probe-preview-optional.json"),
        ],
        cwd=next_dir,
        text=True,
        capture_output=True,
    )
    assert_true(optional_proc.returncode != 0, "apply_next_probes should exit non-zero when an existing optional defects artifact is unreadable.")
    assert_true("Traceback" not in optional_proc.stderr, "apply_next_probes should not expose unreadable optional inputs as a traceback.")
    optional_preview = load_json(next_dir / "next-probe-preview-optional.json")
    optional_names = {item.get("name") for item in optional_preview.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true("defects" in optional_names, "next-probe preview should name unreadable optional defects input.")


def run_environment_boundary_fixture(script_dir: Path, tmp_path: Path) -> None:
    env_dir = tmp_path / "environment-boundary"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (env_dir / "evidence" / "env-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-env",
                "source": "fixture",
                "text": "A real backtest pass must have an explicit runtime and data boundary.",
                "test_ids": ["T-env"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-env",
                "requirement_ids": ["R-env"],
                "type": "api",
                "expected": "A current-run API response passes in a declared test environment.",
                "status": "Untested",
            }
        ],
    }
    ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-env",
                "source": "fixture",
                "text": matrix["requirements"][0]["text"],
                "test_ids": ["T-env"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "tests": [
            {
                "id": "T-env",
                "requirement_ids": ["R-env"],
                "type": "api",
                "expected": matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "evidence": [
            {
                "id": "E-api",
                "type": "api_response",
                "url": "/api/v1/env",
                "body_path": "evidence/env-response.json",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "proves": "The API response proves the declared environment fixture.",
            }
        ],
    }
    defects = {"summary": {"finding_count": 0, "severity_counts": {}}}
    write_json(env_dir / "test-matrix.json", matrix)
    write_json(env_dir / "evidence-ledger.json", ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(env_dir / "test-matrix.json"),
            "--ledger",
            str(env_dir / "evidence-ledger.json"),
            "--summary",
            str(env_dir / "audit-summary.json"),
        ],
        cwd=env_dir,
    )
    write_json(env_dir / "defects.json", defects)

    def verdict_for(name: str, adapter_context: dict[str, Any] | None, extra_args: list[str] | None = None) -> dict[str, Any]:
        context_path = env_dir / f"{name}-adapter-context.json"
        if adapter_context is not None:
            write_json(context_path, adapter_context)
        cmd = [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(env_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(env_dir / "audit-summary.json"),
            "--defects",
            str(env_dir / "defects.json"),
            "--out",
            str(env_dir / f"{name}-verdict.json"),
            "--require-environment-boundary",
        ]
        if adapter_context is not None:
            cmd.extend(["--adapter-context", str(context_path)])
        if extra_args:
            cmd.extend(extra_args)
        run_cmd(cmd, cwd=env_dir)
        return load_json(env_dir / f"{name}-verdict.json")

    missing = verdict_for("missing", None)
    assert_true(missing.get("can_claim_pass") is False, "Required environment boundary should block pass when adapter-context.json is missing.")
    assert_true("missing_environment_boundary" in {reason.get("code") for reason in missing.get("reasons", [])}, "Missing adapter context should produce a specific reason code.")

    unconfirmed_context = {
        "environment_boundary": {
            "runtime_mode": "unconfirmed",
            "data_boundary_status": "must be stated before pass/fail",
        }
    }
    unconfirmed = verdict_for("unconfirmed", unconfirmed_context)
    unconfirmed_codes = {reason.get("code") for reason in unconfirmed.get("reasons", [])}
    assert_true({"environment_unconfirmed", "data_boundary_unconfirmed"}.issubset(unconfirmed_codes), "Unconfirmed runtime/data boundary should block pass.")

    partial_context = {
        "environment_boundary": {
            "runtime_mode": "local",
            "data_boundary_status": "must be stated before pass/fail",
        }
    }
    partial = verdict_for("partial", partial_context)
    assert_true("data_boundary_unconfirmed" in {reason.get("code") for reason in partial.get("reasons", [])}, "Runtime-only boundary should still require data boundary.")

    confirmed_context = {
        "environment_boundary": {
            "runtime_mode": "local",
            "data_boundary_status": "test database with local seed data; no production data",
        }
    }
    confirmed = verdict_for("confirmed", confirmed_context)
    assert_true(confirmed.get("can_claim_pass") is True, "Confirmed runtime and data boundary should allow a clean pass verdict.")
    assert_true(confirmed.get("gates", {}).get("environment_boundary_confirmed") is True, "Verdict gates should expose confirmed environment boundary.")

    cycle_dir = tmp_path / "environment-boundary-cycle"
    (cycle_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (cycle_dir / "requirement.md").write_text(f"- {matrix['requirements'][0]['text']}\n", encoding="utf-8")
    (cycle_dir / "evidence" / "env-cycle-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(cycle_dir / "test-matrix.json", matrix)
    write_json(
        cycle_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(cycle_dir),
            "scenarios": [
                {
                    "id": "env",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-env-api",
                            "testIds": ["T-env"],
                            "requirementIds": ["R-env"],
                            "path": "/api/v1/env",
                            "evidenceType": "api_response",
                            "proves": "The API response proves the declared environment fixture.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        cycle_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(cycle_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "env",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "env",
                            "stepId": "T-env-api",
                            "testIds": ["T-env"],
                            "requirementIds": ["R-env"],
                            "action": "api",
                            "status": "passed",
                            "evidenceType": "api_response",
                            "url": "http://127.0.0.1:9527/api/v1/env",
                            "statusCode": 200,
                            "bodyPath": str(cycle_dir / "evidence" / "env-cycle-response.json"),
                            "checkedJson": {"ok": True},
                            "proves": "The API response proves the declared environment fixture.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(cycle_dir / "adapter-context.json", unconfirmed_context)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(cycle_dir),
            "--skip-probe",
            "--strict-runtime",
            "--skip-report",
            "--require-environment-boundary",
            "--runtime-mode",
            "local",
            "--data-boundary-status",
            "test database with local seed data; no production data",
        ],
        cwd=cycle_dir,
    )
    cycle_verdict = load_json(cycle_dir / "qa-verdict.json")
    cycle_context = load_json(cycle_dir / "adapter-context.json")
    assert_true(cycle_verdict.get("can_claim_pass") is True, "run_qa_cycle should pass through confirmed environment boundary.")
    assert_true(cycle_context.get("environment_boundary", {}).get("runtime_mode") == "local", "run_qa_cycle should write runtime mode to adapter-context.json.")
    assert_true("test database" in cycle_context.get("environment_boundary", {}).get("data_boundary_status", ""), "run_qa_cycle should write data boundary to adapter-context.json.")


def read_exact(connection: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("Unexpected EOF while reading WebSocket frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_ws_text(connection: Any) -> str:
    first = read_exact(connection, 2)
    opcode = first[0] & 0x0F
    length = first[1] & 0x7F
    masked = bool(first[1] & 0x80)
    if opcode == 8:
        return ""
    if length == 126:
        length = int.from_bytes(read_exact(connection, 2), "big")
    elif length == 127:
        length = int.from_bytes(read_exact(connection, 8), "big")
    mask = read_exact(connection, 4) if masked else b""
    payload = read_exact(connection, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return payload.decode("utf-8")


def send_ws_text(connection: Any, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    if len(payload) < 126:
        header.append(len(payload))
    elif len(payload) < 65536:
        header.append(126)
        header.extend(len(payload).to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(len(payload).to_bytes(8, "big"))
    connection.sendall(bytes(header) + payload)


def run_live_backtest_fixture(script_dir: Path, tmp_path: Path) -> None:
    live_dir = tmp_path / "live-backtest-cycle"
    live_dir.mkdir(parents=True, exist_ok=True)
    store_path = live_dir / "live-store.json"
    marker = "QA_LIVE_STREAM_OK"
    session_id = "session-live-1"
    turn_id = "turn-live-1"
    state: dict[str, Any] = {
        "sessions": {},
        "received_payloads": [],
        "store_path": store_path,
    }

    class LiveFixtureHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def send_json(self, status: int, value: dict[str, Any]) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/v1/agents/ask/ws":
                self.handle_websocket()
                return
            if path == "/api/v1/agents/catalog":
                self.send_json(200, {"agents": [{"id": "agent-live", "name": "Live QA Agent"}]})
                return
            if path.startswith("/api/v1/sessions/"):
                wanted_session = path.rsplit("/", 1)[-1]
                session = state["sessions"].get(wanted_session)
                if session:
                    self.send_json(200, session)
                else:
                    self.send_json(404, {"error": "session_not_found", "id": wanted_session})
                return
            self.send_json(200, {"ok": True})

        def handle_websocket(self) -> None:
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()

            raw_request = read_ws_text(self.connection)
            try:
                request_payload = json.loads(raw_request)
            except json.JSONDecodeError:
                request_payload = {"raw": raw_request}
            state["received_payloads"].append(request_payload)
            question = str(request_payload.get("question") or "")
            returned_marker = marker if marker in question else f"{marker}_MISSING_FROM_INPUT"
            answer = f"fixture answer contains {returned_marker}"
            session = {
                "id": session_id,
                "session_id": session_id,
                "status": "completed",
                "messages": [
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer},
                ],
                "turns": [{"id": turn_id, "status": "completed", "answer": answer}],
            }
            state["sessions"][session_id] = session
            store_path.write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "turn_id": turn_id,
                        "status": "completed",
                        "message_count": 2,
                        "answer": answer,
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            send_ws_text(self.connection, json.dumps({"type": "answer_chunk", "delta": answer}, ensure_ascii=False))
            send_ws_text(
                self.connection,
                json.dumps(
                    {
                        "type": "answer_done",
                        "session_id": session_id,
                        "turn_id": turn_id,
                        "status": "completed",
                        "answer": answer,
                    },
                    ensure_ascii=False,
                ),
            )
            self.connection.sendall(b"\x88\x00")

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadedHTTPServer(("127.0.0.1", 0), LiveFixtureHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    helper_path = live_dir / "check_persistence.py"
    helper_path.write_text(
        """#!/usr/bin/env python3
import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--store", required=True)
parser.add_argument("--turn-id", required=True)
args = parser.parse_args()
data = json.load(open(args.store, encoding="utf-8"))
if data.get("turn_id") != args.turn_id:
    print(json.dumps({"status": "wrong_turn", "expected": args.turn_id, "actual": data.get("turn_id")}))
    sys.exit(2)
print(json.dumps(data, ensure_ascii=False))
""",
        encoding="utf-8",
    )
    try:
        (live_dir / "requirement.md").write_text(
            "- The live WebSocket stream emits answer_done and returns the current-run marker.\n"
            "- The same session is readable through the session detail API and contains the fixture text.\n"
            "- The same turn reaches completed in the persistence helper.\n",
            encoding="utf-8",
        )
        write_json(
            live_dir / "adapter-context.json",
            {
                "schema_version": 1,
                "adapter": "live_backtest_fixture",
                "base_url": base_url,
                "environment_boundary": {
                    "runtime_mode": "local",
                    "data_boundary_status": "local deterministic fixture data; no production data",
                    "data_boundaries": ["Local in-memory fixture only."],
                },
                "services": [
                    {
                        "id": "live-fixture",
                        "role": "local HTTP/WebSocket fixture",
                        "default_url": base_url,
                        "port": server.server_port,
                        "port_open": True,
                    }
                ],
                "evidence_layers": [
                    {"id": "real_stream_completion", "strong_signal": "answer_done plus marker returned from the WebSocket fixture."},
                    {"id": "persistence_terminal_state", "strong_signal": "Read-only helper observes completed for the same turn_id."},
                ],
            },
        )
        write_json(
            live_dir / "test-matrix.json",
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R-stream",
                        "source": "live fixture",
                        "text": "The live WebSocket stream emits answer_done and returns the current-run marker.",
                        "test_ids": ["T-stream"],
                        "status": "Untested",
                    },
                    {
                        "id": "R-session-api",
                        "source": "live fixture",
                        "text": "The same session is readable through the session detail API and contains the fixture text.",
                        "test_ids": ["T-session-api"],
                        "status": "Untested",
                    },
                    {
                        "id": "R-persistence",
                        "source": "live fixture",
                        "text": "The same turn reaches completed in the persistence helper.",
                        "test_ids": ["T-persistence"],
                        "status": "Untested",
                    },
                ],
                "tests": [
                    {
                        "id": "T-stream",
                        "requirement_ids": ["R-stream"],
                        "type": "stream",
                        "expected": "WebSocket returns the current-run marker and answer_done.",
                        "status": "Untested",
                    },
                    {
                        "id": "T-session-api",
                        "requirement_ids": ["R-session-api"],
                        "type": "api",
                        "expected": "Session detail API returns the fixture text for the same session.",
                        "status": "Untested",
                    },
                    {
                        "id": "T-persistence",
                        "requirement_ids": ["R-persistence"],
                        "type": "persistence",
                        "expected": "Read-only persistence helper returns completed for the same turn_id.",
                        "status": "Untested",
                    },
                ],
            },
        )
        write_json(
            live_dir / "test-plan.json",
            {
                "schemaVersion": 2,
                "baseUrl": base_url,
                "artifactDir": str(live_dir),
                "headless": True,
                "qaMarker": marker,
                "scenarios": [
                    {
                        "id": "live-stream-api-persistence",
                        "continueOnFailure": True,
                        "steps": [
                            {
                                "action": "websocket",
                                "id": "live-stream-answer-done",
                                "testIds": ["T-stream"],
                                "requirementIds": ["R-stream"],
                                "path": "/api/v1/agents/ask/ws",
                                "send": {"question": {"template": "live fixture question {qa_marker}"}},
                                "expectJson": {"type": "answer_done"},
                                "expectMessageTextContains": {"var": "qa_marker"},
                                "finishOnJsonTypes": ["answer_done"],
                                "captureMessages": True,
                                "extractJson": {
                                    "session_id": {"path": "session_id", "matchJson": {"session_id": {"op": "exists"}}},
                                    "turn_id": {"path": "turn_id", "from": "last"},
                                },
                                "evidenceType": "websocket",
                                "proves": "The live stream emits answer_done and returns the current-run marker.",
                            },
                            {
                                "action": "api",
                                "id": "live-session-detail",
                                "testIds": ["T-session-api"],
                                "requirementIds": ["R-session-api"],
                                "method": "GET",
                                "path": {"var": "session_id", "prefix": "/api/v1/sessions/"},
                                "expectStatus": 200,
                                "expectResponseTextContains": {"var": "qa_marker"},
                                "expectJson": {
                                    "id": {"var": "session_id"},
                                    "status": "completed",
                                    "messages[1].content": {"op": "contains", "value": {"var": "qa_marker"}},
                                },
                                "captureBody": True,
                                "evidenceType": "api_response",
                                "proves": "The same session is readable through the API and contains the fixture text.",
                            },
                            {
                                "action": "command",
                                "id": "live-persistence-helper",
                                "testIds": ["T-persistence"],
                                "requirementIds": ["R-persistence"],
                                "command": [
                                    sys.executable,
                                    str(helper_path),
                                    "--store",
                                    str(store_path),
                                    "--turn-id",
                                    {"var": "turn_id"},
                                ],
                                "expectExitCode": 0,
                                "expectStdoutContains": "completed",
                                "expectStdoutJson": {
                                    "turn_id": {"var": "turn_id"},
                                    "status": "completed",
                                    "message_count": {"op": "gte", "value": 2},
                                    "answer": {"op": "contains", "value": {"var": "qa_marker"}},
                                },
                                "extractStdoutJson": {"session_id": "session_id", "turn_id_from_store": "turn_id"},
                                "captureStdout": True,
                                "captureStderr": True,
                                "evidenceType": "command",
                                "proves": "The read-only helper verifies the same turn reached completed persistence state.",
                            },
                        ],
                    }
                ],
            },
        )
        run_cmd(
            [
                sys.executable,
                str(script_dir / "run_qa_cycle.py"),
                "--run-dir",
                str(live_dir),
                "--strict-runtime",
                "--require-environment-boundary",
                "--skip-report",
            ],
            cwd=live_dir,
        )
        verdict = load_json(live_dir / "qa-verdict.json")
        ledger = load_json(live_dir / "evidence-ledger.json")
        audit = load_json(live_dir / "audit-summary.json")
        evidence_by_type = {item.get("type"): item for item in ledger.get("evidence", [])}
        assert_true(verdict.get("can_claim_pass") is True, "Live stream/API/persistence fixture should produce a pass verdict.")
        assert_true(audit.get("passed") is True, "Live fixture evidence audit should pass.")
        assert_true(evidence_by_type.get("websocket", {}).get("message_text_contains_matched") == marker, "Live stream evidence should preserve returned marker signal.")
        assert_true(evidence_by_type.get("api_response", {}).get("response_text_contains_matched") == marker, "Live API evidence should preserve returned marker signal.")
        assert_true(evidence_by_type.get("command", {}).get("checked_stdout_json", {}).get("status") == "completed", "Live persistence evidence should preserve completed status.")
        assert_true((store_path.exists() and marker in store_path.read_text(encoding="utf-8")), "Live fixture should write persisted marker state.")
    finally:
        server.shutdown()
        server.server_close()
