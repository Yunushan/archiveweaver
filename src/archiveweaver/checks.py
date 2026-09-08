from __future__ import annotations

import os
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .catalog import Catalog


COMMAND_ALIASES = {
    "systemd": ["systemctl"],
    "Docker Engine": ["docker"],
    "Docker Compose v2": ["docker"],
    "Podman 4.4+": ["podman"],
    "Corosync": ["corosync", "pcs"],
    "Pacemaker": ["pacemakerd", "pcs"],
    "pcs": ["pcs"],
    "CNI": ["kubectl"],
    "Ingress": ["kubectl"],
    "CSI-backed storage": ["kubectl"],
}


def _command(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(args),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def detect_host() -> dict[str, Any]:
    values: dict[str, str] = {}
    os_release = Path("/etc/os-release")
    if os_release.exists():
        for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return {
        "id": values.get("ID", "unknown"),
        "version_id": values.get("VERSION_ID", "unknown"),
        "pretty_name": values.get("PRETTY_NAME", "unknown"),
        "kernel": _command("uname", "-r")[1] or "unknown",
        "architecture": _command("uname", "-m")[1] or "unknown",
        "hostname": socket.gethostname(),
    }


def _result(name: str, status: str, detail: str, evidence: Any = None) -> dict[str, Any]:
    item = {"name": name, "status": status, "detail": detail}
    if evidence is not None:
        item["evidence"] = evidence
    return item


def check_commands(commands: list[str], name: str = "commands") -> dict[str, Any]:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        return _result(name, "fail", "missing command(s)", {"missing": missing})
    return _result(name, "pass", "all required command(s) are present", {"commands": commands})


def check_service(service: str) -> dict[str, Any]:
    if shutil.which("systemctl") is None:
        return _result(f"service:{service}", "skip", "systemctl is not available")
    code, stdout, stderr = _command("systemctl", "is-active", service)
    if code == 0 and stdout == "active":
        return _result(f"service:{service}", "pass", "active", stdout)
    if code == 3 and stdout in {"inactive", "failed", "activating", "deactivating"}:
        return _result(f"service:{service}", "warn", stdout, stderr or stdout)
    return _result(f"service:{service}", "skip", "service unit not found or not queryable", stderr or stdout)


def check_url(url: str, timeout: int = 8) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _result("http", "fail", "URL must use an http(s) scheme", {"url": url})
    request = urllib.request.Request(url, headers={"User-Agent": "ArchiveWeaver/0.1 health-check"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if 200 <= status < 400:
                return _result("http", "pass", f"HTTP {status}", {"url": url, "status": status})
            return _result("http", "warn", f"HTTP {status}", {"url": url, "status": status})
    except urllib.error.HTTPError as exc:
        status = "warn" if 400 <= exc.code < 500 else "fail"
        detail = "authentication or access response" if status == "warn" else "server error response"
        return _result("http", status, f"HTTP {exc.code} ({detail})", {"url": url, "status": exc.code})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return _result("http", "fail", "request failed; TLS verification was not bypassed", {"url": url, "error": str(exc)})


def _runtime_commands(mode: str) -> list[str]:
    if mode == "raw":
        return ["systemctl"]
    if mode == "docker" or mode == "docker-swarm":
        return ["docker"]
    if mode == "podman-quadlet":
        return ["podman", "systemctl"]
    if mode == "pacemaker":
        return ["pcs", "corosync", "pacemakerd"]
    return ["kubectl"]


def run_checks(
    catalog: Catalog,
    solution_id: str,
    *,
    mode: str | None = None,
    url: str | None = None,
    service: str | None = None,
    paths: list[str] | None = None,
    config: str | None = None,
) -> dict[str, Any]:
    solution = catalog.solution(solution_id)
    checks: list[dict[str, Any]] = []
    host = detect_host()
    checks.append(_result("host", "pass", host["pretty_name"], host))
    if mode:
        catalog.runtime(mode)
        checks.append(check_commands(_runtime_commands(mode), f"runtime:{mode}"))

    aliases = [service] if service else solution["health"]["service_aliases"]
    service_results = [check_service(item) for item in aliases]
    if service_results:
        if any(item["status"] == "pass" for item in service_results):
            checks.extend(service_results)
        else:
            checks.append(_result("services", "skip", "no configured product service is active; pass --service for the exact unit"))
            checks.extend(service_results[:3])

    if url:
        checks.append(check_url(url))
    else:
        checks.append(_result("http", "skip", "no URL supplied; pass --url https://host/path for an endpoint probe"))

    for path in paths or []:
        target = Path(path)
        checks.append(_result(f"path:{path}", "pass" if target.exists() else "fail", "exists" if target.exists() else "missing", {"directory": target.is_dir()} if target.exists() else None))
    if config:
        target = Path(config)
        checks.append(_result("configuration", "pass" if target.exists() else "fail", "exists" if target.exists() else "missing", str(target)))
    else:
        checks.append(_result("configuration", "skip", "no --config path supplied"))

    warnings = [item for item in checks if item["status"] == "warn"]
    failures = [item for item in checks if item["status"] == "fail"]
    return {
        "solution": solution_id,
        "solution_name": solution["name"],
        "mode": mode,
        "host": host,
        "summary": {"status": "fail" if failures else ("warn" if warnings else "pass"), "failures": len(failures), "warnings": len(warnings)},
        "checks": checks,
        "policy": [
            "Checks are read-only and do not repair, restart, migrate, reindex, or delete data.",
            "A passing HTTP check is not evidence that backup, fixity, authorization, OCR, or preservation workflows are healthy.",
        ],
    }
