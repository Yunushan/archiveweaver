from __future__ import annotations

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
    "Ansible Core": ["ansible-playbook"],
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep health probes on the exact operator-supplied endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _open_health_request(request: urllib.request.Request, timeout: int) -> Any:
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return opener.open(request, timeout=timeout)


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
    except (OSError, subprocess.TimeoutExpired) as exc:
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


def check_time_sync() -> dict[str, Any]:
    """Report whether systemd considers the host clock synchronized."""
    if shutil.which("timedatectl") is None:
        return _result("host-time", "skip", "timedatectl is not available")
    code, stdout, stderr = _command(
        "timedatectl",
        "show",
        "--property=NTPSynchronized",
        "--value",
    )
    if code != 0:
        return _result(
            "host-time",
            "warn",
            "time synchronization could not be queried",
            stderr or stdout,
        )
    synchronized = stdout.strip().lower()
    if synchronized == "yes":
        return _result("host-time", "pass", "system clock is synchronized")
    if synchronized == "no":
        return _result("host-time", "fail", "system clock is not synchronized")
    return _result(
        "host-time",
        "warn",
        "time synchronization returned an unknown state",
        stdout,
    )


def _redacted_url(value: Any) -> str:
    """Return a report-safe URL with userinfo, query, and fragment removed."""
    if not isinstance(value, str):
        return "<invalid-url>"
    if any(ord(char) < 0x20 or char in {'"', "\\"} for char in value):
        return "<redacted-url>"
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        if hostname:
            netloc = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
            try:
                port = parsed.port
            except ValueError:
                port = None
            if port is not None:
                netloc = f"{netloc}:{port}"
        else:
            netloc = "<invalid-host>"
        return parsed._replace(netloc=netloc, query="", fragment="").geturl()
    except (TypeError, ValueError):
        return "<invalid-url>"


def _url_scheme(value: Any) -> str:
    try:
        return urlparse(value).scheme if isinstance(value, str) else ""
    except (TypeError, ValueError):
        return ""


def _http_error_url(error: urllib.error.HTTPError) -> str:
    """Read an HTTPError URL without triggering fragile compatibility hooks."""
    try:
        value = error.url
    except (AttributeError, KeyError, OSError, ValueError):
        return ""
    return value if isinstance(value, str) else ""


def check_url(url: str, timeout: int = 8) -> dict[str, Any]:
    reported_url = _redacted_url(url)
    if not isinstance(url, str) or any(ord(char) < 0x20 or char in {'"', "\\"} for char in url):
        return _result("http", "fail", "health URLs must not contain control, quoting, or backslash characters", {"url": reported_url})
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return _result("http", "fail", "URL could not be parsed", {"url": reported_url, "error": type(exc).__name__})
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        return _result("http", "fail", "URL host or port could not be parsed", {"url": reported_url, "error": type(exc).__name__})
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        return _result("http", "fail", "URL must use an http(s) scheme", {"url": reported_url})
    if parsed.username or parsed.password:
        return _result("http", "fail", "health URLs must not contain credentials", {"url": reported_url})
    if parsed.query or parsed.fragment:
        return _result("http", "fail", "health URLs must not contain query or fragment data", {"url": reported_url})
    request = urllib.request.Request(url, headers={"User-Agent": "ArchiveWeaver/0.1 health-check"})
    try:
        with _open_health_request(request, timeout) as response:
            status = getattr(response, "status", 200)
            final_url = response.geturl()
            final_scheme = _url_scheme(final_url)
            if parsed.scheme == "https" and final_scheme != "https":
                return _result(
                    "http",
                    "fail",
                    "HTTPS health check redirected to a non-HTTPS URL",
                    {"url": reported_url, "final_url": _redacted_url(final_url), "status": status},
                )
            if 200 <= status < 300:
                return _result(
                    "http",
                    "pass",
                    f"HTTP {status}",
                    {"url": reported_url, "final_url": _redacted_url(final_url), "status": status},
                )
            return _result(
                "http",
                "warn",
                f"HTTP {status}; health endpoints should return 2xx",
                {"url": reported_url, "final_url": _redacted_url(final_url), "status": status},
            )
    except urllib.error.HTTPError as exc:
        final_url = _http_error_url(exc)
        final_scheme = _url_scheme(final_url)
        if parsed.scheme == "https" and final_scheme and final_scheme != "https":
            return _result(
                "http",
                "fail",
                "HTTPS health check redirected to a non-HTTPS URL",
                {"url": reported_url, "final_url": _redacted_url(final_url), "status": exc.code},
            )
        if 300 <= exc.code < 400:
            return _result(
                "http",
                "fail",
                "health checks do not follow redirects",
                {"url": reported_url, "status": exc.code},
            )
        status = "warn" if 400 <= exc.code < 500 else "fail"
        detail = "authentication or access response" if status == "warn" else "server error response"
        return _result("http", status, f"HTTP {exc.code} ({detail})", {"url": reported_url, "status": exc.code})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return _result("http", "fail", "request failed; TLS verification was not bypassed", {"url": reported_url, "error": type(exc).__name__})


def _runtime_commands(mode: str) -> list[str]:
    if mode == "raw":
        return ["systemctl"]
    if mode == "docker" or mode == "docker-swarm":
        return ["docker"]
    if mode == "podman-quadlet":
        return ["podman", "systemctl"]
    if mode == "pacemaker":
        return ["pcs", "corosync", "pacemakerd"]
    if mode == "ansible":
        return ["ansible-playbook"]
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
    checks.append(check_time_sync())
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
    skipped = [item for item in checks if item["status"] == "skip"]
    meaningful_passes = [
        item
        for item in checks
        if item["status"] == "pass"
        and (
            item["name"].startswith("service:")
            or item["name"].startswith("path:")
            or item["name"] in {"http", "configuration"}
        )
    ]
    summary_status = (
        "fail"
        if failures
        else ("warn" if warnings or not meaningful_passes else "pass")
    )
    return {
        "solution": solution_id,
        "solution_name": solution["name"],
        "mode": mode,
        "host": host,
        "summary": {
            "status": summary_status,
            "failures": len(failures),
            "warnings": len(warnings),
            "skipped": len(skipped),
            "meaningful_passes": len(meaningful_passes),
        },
        "checks": checks,
        "policy": [
            "Checks are read-only and do not repair, restart, migrate, reindex, or delete data.",
            "A passing HTTP check is not evidence that backup, fixity, authorization, OCR, or preservation workflows are healthy.",
        ],
    }
