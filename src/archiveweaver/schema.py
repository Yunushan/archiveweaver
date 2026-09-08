from __future__ import annotations

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


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


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

    for solution in catalog.solutions.values():
        prefix = f"solution '{solution.get('id', '<missing>')}'"
        missing = REQUIRED_SOLUTION_FIELDS - set(solution)
        errors.extend(f"{prefix} missing field '{field}'" for field in sorted(missing))
        for field in ("upstream_repo", "source_repo", "official_docs", "homepage"):
            if field in solution and not _is_url(solution[field]):
                errors.append(f"{prefix} field '{field}' must be an http(s) URL")
        list_fields = ("architecture_components", "format_profiles", "dependencies", "notes")
        for field in list_fields:
            value = solution.get(field)
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                errors.append(f"{prefix} field '{field}' must be a list of non-empty strings")
        profiles = solution.get("format_profiles", []) if isinstance(solution.get("format_profiles"), list) else []
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
            elif modes[mode] not in {"native", "validated", "portable", "conditional", "not-recommended"}:
                errors.append(f"{prefix} has invalid support level '{modes[mode]}' for '{mode}'")
        health = solution.get("health", {})
        if not isinstance(health, dict):
            errors.append(f"{prefix} field 'health' must be an object")
            health = {}
        if not isinstance(health.get("service_aliases"), list):
            errors.append(f"{prefix} health.service_aliases must be a list")
        if not isinstance(health.get("http_paths"), list):
            errors.append(f"{prefix} health.http_paths must be a list")

    for runtime in catalog.runtimes.values():
        prefix = f"runtime '{runtime.get('id', '<missing>')}'"
        for bucket in ("1", "2", "3", "3+"):
            if bucket not in runtime.get("topology", {}):
                errors.append(f"{prefix} missing topology bucket '{bucket}'")
        if runtime.get("kind") not in {"native", "container", "kubernetes", "cluster-manager", "container-orchestrator", "automation"}:
            errors.append(f"{prefix} has an unknown kind")

    return errors

