#!/usr/bin/env python3
import argparse
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


OPC_SERVICES = [
    {
        "id": "one_corpus_web",
        "role": "user-facing Vite app",
        "path": "one_corpus_web",
        "default_url": "http://127.0.0.1:9527",
        "start_command": "npm run dev",
    },
    {
        "id": "opc-bot",
        "role": "Go Gin business API",
        "path": "opc-bot",
        "default_url": "http://127.0.0.1:8081",
        "start_command": "go run ./cmd/bot-chat",
    },
    {
        "id": "agent_platform",
        "role": "FastAPI agent engine",
        "path": "agent_platform",
        "default_url": "http://127.0.0.1:8000",
        "start_command": "python -m app.main",
    },
    {
        "id": "ops_web",
        "role": "operations console",
        "path": "ops_web",
        "default_url": "http://127.0.0.1:3070",
        "start_command": "npm run dev",
    },
]
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def iter_project_files(root: Path, max_depth: int = 4):
    def walk(directory: Path, depth: int):
        if depth > max_depth:
            return
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            return
        for child in children:
            if child.is_dir():
                if child.name not in SKIP_DIRS:
                    yield from walk(child, depth + 1)
            elif child.is_file():
                yield child

    yield from walk(root, 0)


def find_files(root: Path, names: set[str], max_depth: int = 4) -> list[str]:
    return sorted(rel(path, root) for path in iter_project_files(root, max_depth) if path.name in names)


def find_env_files(root: Path, max_depth: int = 4) -> list[str]:
    return sorted(rel(path, root) for path in iter_project_files(root, max_depth) if path.name.startswith(".env"))


def read_package_summary(path: Path, root: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"path": rel(path, root), "error": f"Could not parse package.json: {exc}"}
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    useful_scripts = {
        name: scripts[name]
        for name in sorted(scripts)
        if name in {"dev", "start", "test", "build", "lint"} or name.startswith("test")
    }
    return {
        "path": rel(path, root),
        "name": data.get("name"),
        "scripts": useful_scripts,
    }


def parse_url_port(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_probe(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "ok": 200 <= response.status < 500,
                "status": response.status,
                "reason": response.reason,
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": exc.code < 500,
            "status": exc.code,
            "reason": exc.reason,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc)[:240],
        }


def service_status(service: dict[str, Any], root: Path, timeout: float, probe_http: bool) -> dict[str, Any]:
    url = service.get("default_url", "")
    parsed = urllib.parse.urlparse(url)
    port = parse_url_port(url)
    item = {
        **service,
        "path_exists": (root / service.get("path", "")).exists(),
        "port": port,
        "port_open": False,
    }
    if parsed.hostname and port:
        item["port_open"] = tcp_open(parsed.hostname, port, timeout)
    if probe_http:
        item["http_probe"] = http_probe(url, timeout)
    return item


def detect_adapter(root: Path) -> str:
    opc_markers = ["one_corpus_web/package.json", "opc-bot/go.mod", "agent_platform/pyproject.toml"]
    if all((root / marker).exists() for marker in opc_markers):
        return "opc_project"
    return "generic"


def generic_services(root: Path) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for package_path in [root / item for item in find_files(root, {"package.json"})]:
        services.append({
            "id": rel(package_path.parent, root).replace("/", "-") or "node-app",
            "role": "Node/Vite/React app or package",
            "path": rel(package_path.parent, root),
            "default_url": "",
            "start_command": "npm run dev",
        })
    for go_mod in [root / item for item in find_files(root, {"go.mod"})]:
        services.append({
            "id": rel(go_mod.parent, root).replace("/", "-") or "go-service",
            "role": "Go service or module",
            "path": rel(go_mod.parent, root),
            "default_url": "",
            "start_command": "go test ./...",
        })
    for pyproject in [root / item for item in find_files(root, {"pyproject.toml"})]:
        services.append({
            "id": rel(pyproject.parent, root).replace("/", "-") or "python-service",
            "role": "Python service or package",
            "path": rel(pyproject.parent, root),
            "default_url": "",
            "start_command": "python -m pytest",
        })
    return services


def opc_evidence_layers() -> list[dict[str, str]]:
    return [
        {
            "id": "environment_boundary",
            "strong_signal": "Report states local/test/staging/prod and mock/seed/real data boundary before pass/fail.",
            "weak_signal_to_avoid": "A generic pass/fail without naming the runtime data boundary.",
        },
        {
            "id": "catalog_ui_seed",
            "strong_signal": "Visible agent/card state is tied to current UI/API/seed evidence.",
            "weak_signal_to_avoid": "Treating hardcoded cards or local seed rows as online production configuration.",
        },
        {
            "id": "frontend_fallback",
            "strong_signal": "Rendered reply is identified as real stream output or explicitly labeled fallback/optimistic UI.",
            "weak_signal_to_avoid": "Counting fallback text as backend completion.",
        },
        {
            "id": "real_stream_completion",
            "strong_signal": "WebSocket/SSE/HTTP stream emits answer_chunk and terminal answer_done for the same run marker.",
            "weak_signal_to_avoid": "Matching the unique marker only in user input or prompt text.",
        },
        {
            "id": "persistence_terminal_state",
            "strong_signal": "Read-only persistence/log evidence shows the same session/turn reaches completed.",
            "weak_signal_to_avoid": "Inferring DB completion from a successful screenshot.",
        },
    ]


def generic_evidence_layers() -> list[dict[str, str]]:
    return [
        {
            "id": "environment_boundary",
            "strong_signal": "Report states runtime environment and data boundary before pass/fail.",
            "weak_signal_to_avoid": "A generic pass/fail without naming data source limits.",
        },
        {
            "id": "ui_runtime",
            "strong_signal": "Current-run screenshots plus console/network checks for each user-facing requirement.",
            "weak_signal_to_avoid": "Static screenshots without interaction or runtime checks.",
        },
        {
            "id": "api_data_flow",
            "strong_signal": "API/log/persistence evidence verifies data-dependent requirements.",
            "weak_signal_to_avoid": "Inferring backend correctness from visible text alone.",
        },
    ]


def project_root_errors(root: Path) -> list[dict[str, str]]:
    if not root.exists():
        return [{"name": "project_root", "path": str(root), "error": "missing"}]
    if not root.is_dir():
        return [{"name": "project_root", "path": str(root), "error": "path_is_not_directory"}]
    try:
        next(root.iterdir(), None)
    except OSError as exc:
        return [{"name": "project_root", "path": str(root), "error": f"read_error: {exc}"}]
    return []


def discover_context(
    project_root: Path,
    base_url: str | None = None,
    probe_http: bool = True,
    timeout: float = 0.8,
    runtime_mode: str | None = None,
    data_boundary_status: str | None = None,
) -> dict[str, Any]:
    root = project_root.expanduser().resolve()
    input_errors = project_root_errors(root)
    adapter = detect_adapter(root)
    package_files = [root / item for item in find_files(root, {"package.json"})]
    config_files = find_files(root, {"go.mod", "pyproject.toml", "config.yaml", "docker-compose.yml", "docker-compose.yaml"})
    env_files = find_env_files(root)
    service_templates = OPC_SERVICES if adapter == "opc_project" else generic_services(root)
    services: list[dict[str, Any]] = []
    for service in service_templates:
        if service.get("default_url"):
            services.append(service_status(service, root, timeout, probe_http))
        else:
            services.append({**service, "path_exists": (root / service.get("path", "")).exists(), "port": None, "port_open": None})

    if base_url:
        known = {service.get("default_url") for service in services}
        if base_url not in known:
            port = parse_url_port(base_url)
            parsed = urllib.parse.urlparse(base_url)
            custom = {
                "id": "requested_base_url",
                "role": "base URL supplied for this QA run",
                "path": "",
                "default_url": base_url,
                "path_exists": True,
                "port": port,
                "port_open": False,
            }
            if parsed.hostname and port:
                custom["port_open"] = tcp_open(parsed.hostname, port, timeout)
            if probe_http:
                custom["http_probe"] = http_probe(base_url, timeout)
            services.insert(0, custom)

    package_summaries = [read_package_summary(path, root) for path in package_files]
    data_boundaries = [
        "Runtime secrets and endpoints must remain in env/config files.",
        "State whether this run uses local, test, staging, or production data before pass/fail.",
    ]
    if adapter == "opc_project":
        data_boundaries.extend([
            "PostgreSQL owns user-editable platform data and chat/session state.",
            "Elasticsearch owns knowledge metadata/chunks.",
            "MinIO owns uploaded/generated files.",
            "Redis is cache only.",
            "one_corpus_web /api/v1/* normally proxies to opc-bot on 127.0.0.1:8081.",
        ])

    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "project_root": str(root),
        "project_root_status": {
            "exists": root.exists(),
            "is_dir": root.is_dir(),
            "readable": not input_errors,
        },
        "adapter": adapter,
        "base_url": base_url,
        "environment_boundary": {
            "runtime_mode": runtime_mode or "unconfirmed",
            "data_boundary_status": data_boundary_status or "must be stated before pass/fail",
            "data_boundaries": data_boundaries,
        },
        "discovered_files": {
            "env_files": env_files,
            "config_files": config_files,
            "package_files": [rel(path, root) for path in package_files],
            "package_summaries": package_summaries,
        },
        "services": services,
        "evidence_layers": opc_evidence_layers() if adapter == "opc_project" else generic_evidence_layers(),
        "unsafe_shortcuts": [
            "Do not use UI text alone to prove backend/data completion.",
            "Do not treat seed data, fallback UI, stream terminal events, and persistence as one combined pass signal.",
            "Do not expose tokens, cookies, passwords, or config secret values in artifacts.",
            "Do not mutate production or shared data without explicit authorization and cleanup strategy.",
        ],
        "planning_notes": [
            "Map each data-dependent requirement to API, stream, log, or persistence evidence.",
            "Use unique run markers and verify they appear in returned output, not only in submitted input.",
            "Mark missing credentials, stopped services, or unsafe mutation needs as Blocked rather than Passed.",
        ],
        "input_artifact_errors": input_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover project adapter context for an automated QA/backtest artifact.")
    parser.add_argument("--project-root", default=".", help="Project checkout to inspect.")
    parser.add_argument("--run-dir", help="When provided, write adapter-context.json under this directory.")
    parser.add_argument("--out", help="Explicit output JSON path.")
    parser.add_argument("--base-url", help="Base URL planned for the QA run.")
    parser.add_argument("--runtime-mode", help="Declared runtime mode, for example local, test, staging, production, or ci.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary, for example local seed data, test database, staging real-like data, or production read-only.")
    parser.add_argument("--no-http-probe", action="store_true", help="Skip HTTP GET probes and only inspect files/ports.")
    parser.add_argument("--timeout", type=float, default=0.8)
    args = parser.parse_args()

    context = discover_context(
        project_root=Path(args.project_root),
        base_url=args.base_url,
        probe_http=not args.no_http_probe,
        timeout=args.timeout,
        runtime_mode=args.runtime_mode,
        data_boundary_status=args.data_boundary_status,
    )
    out_path: Path | None = None
    if args.out:
        out_path = Path(args.out).expanduser()
    elif args.run_dir:
        out_path = Path(args.run_dir).expanduser() / "adapter-context.json"
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
        print(out_path)
    else:
        print(json.dumps(context, indent=2, ensure_ascii=False))
    return 1 if context.get("input_artifact_errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
