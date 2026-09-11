from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .catalog import Catalog


REQUIRED_SOLUTION_FIELDS = {
    "id",
    "name",
    "category",
    "upstream_repo",
    "source_repo",
    "official_docs",
    "homepage",
    "license",
    "architecture_components",
    "format_profiles",
    "dependencies",
    "health",
    "mode_support",
    "notes",
}
SUPPORT_LEVELS = {"native", "validated", "portable", "conditional", "not-recommended"}
RUNTIME_KINDS = {
    "native",
    "container",
    "kubernetes",
    "cluster-manager",
    "container-orchestrator",
    "automation",
}
TOPOLOGY_LEVELS = {"supported", "supported-with-stonith", "conditional", "not-recommended"}
OS_TIERS = {"preferred", "validated-base", "forward-validate", "legacy-conditional"}


def _is_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(_is_non_empty_string(item) for item in value)


def validate_catalog(catalog: Catalog) -> list[str]:
    errors: list[str] = []
    solution_ids = list(catalog.solutions)
    if len(solution_ids) != len(set(solution_ids)):
        errors.append("solution ids must be unique")
    runtime_ids = list(catalog.runtimes)
    if len(runtime_ids) != len(set(runtime_ids)):
        errors.append("runtime ids must be unique")
    os_ids = list(catalog.operating_systems)
    if len(os_ids) != len(set(os_ids)):
        errors.append("operating-system ids must be unique")

    for solution_key, solution in catalog.solutions.items():
        prefix = f"solution '{solution.get('id', '<missing>')}'"
        missing = REQUIRED_SOLUTION_FIELDS - set(solution)
        errors.extend(f"{prefix} missing field '{field}'" for field in sorted(missing))
        if not _is_non_empty_string(solution.get("id")):
            errors.append(f"{prefix} field 'id' must be a non-empty string")
        elif solution["id"] != solution_key:
            errors.append(f"{prefix} id does not match catalog key '{solution_key}'")
        for field in ("name", "category", "license"):
            if not _is_non_empty_string(solution.get(field)):
                errors.append(f"{prefix} field '{field}' must be a non-empty string")
        for field in ("upstream_repo", "source_repo", "official_docs", "homepage"):
            if field in solution and not _is_url(solution[field]):
                errors.append(f"{prefix} field '{field}' must be an http(s) URL")
        list_fields = ("architecture_components", "format_profiles", "dependencies", "notes")
        for field in list_fields:
            value = solution.get(field)
            if not _is_string_list(value):
                errors.append(f"{prefix} field '{field}' must be a list of non-empty strings")
        profiles = (
            solution.get("format_profiles", [])
            if isinstance(solution.get("format_profiles"), list)
            else []
        )
        for profile in profiles:
            if profile not in catalog.formats:
                errors.append(f"{prefix} references unknown format profile '{profile}'")
        modes = solution.get("mode_support", {})
        if not isinstance(modes, dict):
            errors.append(f"{prefix} field 'mode_support' must be an object")
            modes = {}
        for mode in catalog.runtimes:
            if mode not in modes:
                errors.append(f"{prefix} missing mode support for '{mode}'")
            elif modes[mode] not in SUPPORT_LEVELS:
                errors.append(f"{prefix} has invalid support level '{modes[mode]}' for '{mode}'")
        for mode in sorted(set(modes) - set(catalog.runtimes)):
            errors.append(f"{prefix} declares unknown mode support for '{mode}'")
        health = solution.get("health", {})
        if not isinstance(health, dict):
            errors.append(f"{prefix} field 'health' must be an object")
            health = {}
        for field in ("service_aliases", "http_paths", "checks"):
            if not _is_string_list(health.get(field)):
                errors.append(
                    f"{prefix} health.{field} must be a list of non-empty strings"
                )
        http_paths = health.get("http_paths")
        if isinstance(http_paths, list):
            for path in http_paths:
                if isinstance(path, str) and not path.startswith("/"):
                    errors.append(f"{prefix} health HTTP path must start with '/': {path}")
        port = health.get("default_port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            errors.append(f"{prefix} health.default_port must be an integer from 1 to 65535")

    for runtime_key, runtime in catalog.runtimes.items():
        prefix = f"runtime '{runtime.get('id', '<missing>')}'"
        if not _is_non_empty_string(runtime.get("id")):
            errors.append(f"{prefix} field 'id' must be a non-empty string")
        elif runtime["id"] != runtime_key:
            errors.append(f"{prefix} id does not match catalog key '{runtime_key}'")
        for field in ("name", "notes"):
            if not _is_non_empty_string(runtime.get(field)):
                errors.append(f"{prefix} field '{field}' must be a non-empty string")
        if not _is_string_list(runtime.get("prerequisites")):
            errors.append(
                f"{prefix} field 'prerequisites' must be a list of non-empty strings"
            )
        topology = runtime.get("topology")
        if not isinstance(topology, dict):
            errors.append(f"{prefix} field 'topology' must be an object")
            topology = {}
        for bucket in ("1", "2", "3", "3+"):
            if bucket not in topology:
                errors.append(f"{prefix} missing topology bucket '{bucket}'")
            elif topology[bucket] not in TOPOLOGY_LEVELS:
                errors.append(
                    f"{prefix} has invalid topology level '{topology[bucket]}' "
                    f"for bucket '{bucket}'"
                )
        for bucket in sorted(set(topology) - {"1", "2", "3", "3+"}):
            errors.append(f"{prefix} declares unknown topology bucket '{bucket}'")
        if runtime.get("kind") not in RUNTIME_KINDS:
            errors.append(f"{prefix} has an unknown kind")

    for os_key, operating_system in catalog.operating_systems.items():
        prefix = f"operating system '{operating_system.get('id', '<missing>')}'"
        if not _is_non_empty_string(operating_system.get("id")):
            errors.append(f"{prefix} field 'id' must be a non-empty string")
        elif operating_system["id"] != os_key:
            errors.append(f"{prefix} id does not match catalog key '{os_key}'")
        for field in ("name", "family"):
            if not _is_non_empty_string(operating_system.get(field)):
                errors.append(f"{prefix} field '{field}' must be a non-empty string")
        if operating_system.get("tier") not in OS_TIERS:
            errors.append(f"{prefix} has an unknown support tier")

    for format_key, format_profile in catalog.formats.items():
        prefix = f"format profile '{format_key}'"
        if not _is_non_empty_string(format_key):
            errors.append("format profile ids must be non-empty strings")
        for field in ("label", "extensions", "mime_examples"):
            if not _is_non_empty_string(format_profile.get(field)):
                errors.append(f"{prefix} field '{field}' must be a non-empty string")

    return errors

