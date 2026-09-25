from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .catalog import Catalog
from .evidence import _measure_regular_file, _read_stable_bytes, verify_evidence_index
from .json_utils import load_json_document
from .path_utils import has_symlink_component


PLACEHOLDER_RE = re.compile(r"(?:replace|todo|tbd|example\.invalid|latest)", re.IGNORECASE)
WINDOWS_ABSOLUTE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]{2})")
RFC3339_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_VERSION = "SPDX-2.3"
SUPPORTED_CYCLONEDX_VERSIONS = frozenset({"1.6", "1.7"})
SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9][A-Za-z0-9.-]*$")
SPDX_CREATED_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
SPDX_CREATOR_RE = re.compile(r"^(?:Person|Organization|Tool):\s*\S")
CYCLONEDX_SERIAL_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
CYCLONEDX_COMPONENT_TYPES = frozenset(
    {
        "application",
        "framework",
        "library",
        "container",
        "platform",
        "operating-system",
        "device",
        "device-driver",
        "firmware",
        "file",
        "machine-learning-model",
        "data",
        "cryptographic-asset",
    }
)
OCI_IMAGE_DIGEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$")
OCI_REPOSITORY_SEGMENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
OCI_RELEASE_IMAGE_RE = re.compile(
    rf"^[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]*)?"
    rf"(?:/{OCI_REPOSITORY_SEGMENT})+@sha256:[0-9a-f]{{64}}$"
)
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_PROOF_RUNTIME_IDS = frozenset(
    {"docker", "docker-swarm", "k3s", "rke2", "k0s", "microk8s"}
)
STATUS_VALUES = {"pass", "pending", "fail"}
ENVIRONMENT_VALUES = {"production", "staging", "restore", "dr"}
APPROVAL_CLOCK_SKEW = timedelta(minutes=5)
APPROVAL_MAX_VALIDITY = timedelta(days=30)
GITHUB_AUDIT_MAX_AGE = timedelta(hours=24)
EVIDENCE_MAX_AGE_BY_SECTION = {
    "control": timedelta(hours=24),
    "release": timedelta(days=30),
    "product_certification": timedelta(days=90),
    "resilience": timedelta(days=90),
    "data_protection": timedelta(days=30),
    "security": timedelta(days=30),
    "observability": timedelta(days=30),
    "recovery": timedelta(days=90),
    "governance": timedelta(days=30),
    "support": timedelta(days=90),
}
EVIDENCE_MAX_AGE_OVERRIDES = {
    "data_protection.backup": timedelta(hours=24),
    "data_protection.restore_test": timedelta(days=90),
    "data_protection.fixity_test": timedelta(days=30),
    "security.vulnerability_scan": timedelta(days=7),
    "security.penetration_test": timedelta(days=365),
    "observability.alert_delivery_test": timedelta(days=30),
}
MAX_READINESS_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_STRUCTURED_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_MANIFEST_JSON_NODES = 100_000
MAX_EVIDENCE_JSON_NODES = 1_000_000
GITHUB_AUDIT_API_VERSION = "2026-03-10"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
SIGSTORE_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_COSIGN_BINARY_BYTES = 256 * 1024 * 1024
MAX_SIGNING_POLICY_BYTES = 1024 * 1024
MAX_SIGSTORE_TRUSTED_ROOT_BYTES = 16 * 1024 * 1024
SIGNING_ROLES = frozenset(
    {
        "release-artifact",
        "provider-bundle",
        "rollback-artifact",
        "execution-environment",
        "operational-evidence",
    }
)
GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
KUBERNETES_NAMESPACE_UID_RE = re.compile(
    r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
DEPLOYMENT_TARGET_FIELDS = frozenset(
    {
        "kube_context",
        "kubeconfig_sha256",
        "inventory_sha256",
        "namespace",
        "kube_system_namespace_uid",
        "application_namespace_uid",
    }
)
GITHUB_AUDIT_CONTROL_NAMES = frozenset(
    {
        "repository",
        "secret-scanning",
        "actions-policy",
        "actions-allowlist",
        "workflow-token",
        "vulnerability-alerts",
        "dependabot-security-updates",
        "private-vulnerability-reporting",
        "immutable-releases",
        "release-environment",
        "main-ruleset",
        "release-tag-ruleset",
    }
)
GITHUB_AUDIT_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "api_version",
        "audited_at",
        "repository",
        "repository_id",
        "repository_node_id",
        "source_revision",
        "passed",
        "controls",
    }
)
GITHUB_AUDIT_CONTROL_FIELDS = frozenset({"name", "passed", "detail"})
GITHUB_AUDIT_REFERENCE_FIELDS = frozenset(
    {
        "path",
        "digest",
        "signature",
        "signature_verified",
        "signature_verification",
    }
)
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "service",
    "evidence_index",
    "evidence_index_digest",
    "control",
    "release",
    "product_certification",
    "resilience",
    "data_protection",
    "security",
    "observability",
    "recovery",
    "governance",
    "support",
}
EvidenceContext = tuple[Path, dict[str, tuple[int, str]], Catalog]
CLAIM_EVIDENCE_FIELDS: dict[str, tuple[str, ...]] = {
    "security": (
        "sbom_verification",
        "tls_verification",
        "secrets_provider_verification",
    ),
    "observability": (
        "metrics_verification",
        "alerts_verification",
        "dashboards_verification",
        "on_call_verification",
    ),
    "support": (
        "service_owner_verification",
        "on_call_verification",
        "sla_verification",
    ),
}
_SECRET_MANIFEST_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secrets",
        "token",
        "privatekey",
        "clientsecret",
        "apitoken",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "credential",
        "credentials",
        "secretvalue",
        "passwordvalue",
        "tokenvalue",
        "signingkey",
        "encryptionkey",
    }
)
_SECRET_MANIFEST_SUFFIXES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "privatekey",
        "apikey",
        "accesskey",
        "credential",
    }
)


def _json_shape_errors(
    value: Any,
    label: str,
    *,
    max_nodes: int,
) -> list[str]:
    """Bound JSON depth and node count before recursive semantic checks."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return [f"{label} exceeds the {max_nodes}-node safety limit"]
        if depth > MAX_JSON_DEPTH:
            return [f"{label} exceeds the {MAX_JSON_DEPTH}-level nesting limit"]
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return []


def _has_structured_release_execution_environment(value: Any) -> bool:
    """Recognize the release section's nested controller-image metadata."""
    return bool(
        isinstance(value, dict)
        and isinstance(value.get("execution_environment"), dict)
        and "artifacts" in value
        and "provider_bundle" in value
    )


def _is_real_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not PLACEHOLDER_RE.search(value)


def _paperless_rke2_production(manifest: dict[str, Any]) -> bool:
    service = manifest.get("service")
    return bool(
        isinstance(service, dict)
        and service.get("solution_id") == "paperless-ngx"
        and service.get("runtime") == "ansible"
        and service.get("underlying_runtime") == "rke2"
        and service.get("environment") == "production"
    )


def _namespace_uid_ok(value: Any) -> bool:
    return bool(
        _is_real_text(value)
        and KUBERNETES_NAMESPACE_UID_RE.fullmatch(value)
        and value != "00000000-0000-0000-0000-000000000000"
    )


def _deployment_target_errors(manifest: dict[str, Any]) -> list[str]:
    """Bind a production score to one protected Kubernetes cluster and namespace."""
    if not _paperless_rke2_production(manifest):
        return []
    target = manifest.get("deployment_target")
    observability = manifest.get("observability")
    observability_pass = (
        isinstance(observability, dict) and observability.get("status") == "pass"
    )
    if target is None:
        return (["deployment_target is required for production 100-point certification"]
                if observability_pass else [])
    if not isinstance(target, dict):
        return ["deployment_target must be an object"]
    errors: list[str] = []
    if set(target) != DEPLOYMENT_TARGET_FIELDS:
        errors.append("deployment_target must contain exactly the six approved target fields")
    context = target.get("kube_context")
    if not (
        isinstance(context, str)
        and _is_real_text(context)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:-]{0,252}", context)
    ):
        errors.append("deployment_target.kube_context must identify a non-placeholder context")
    for field in ("kubeconfig_sha256", "inventory_sha256"):
        value = target.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            errors.append(f"deployment_target.{field} must be a lowercase SHA-256 digest")
    namespace = target.get("namespace")
    if not (
        isinstance(namespace, str)
        and _is_real_text(namespace)
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace)
    ):
        errors.append("deployment_target.namespace must identify a non-placeholder namespace")
    system_uid = target.get("kube_system_namespace_uid")
    if not _namespace_uid_ok(system_uid):
        errors.append("deployment_target.kube_system_namespace_uid must be a non-placeholder Kubernetes UID")
    app_uid = target.get("application_namespace_uid")
    prebootstrap = (
        not observability_pass
        and isinstance(manifest.get("bootstrap_authorization"), dict)
        and app_uid is None
    )
    if not prebootstrap and not _namespace_uid_ok(app_uid):
        errors.append("deployment_target.application_namespace_uid must be a non-placeholder Kubernetes UID")
    if _namespace_uid_ok(system_uid) and _namespace_uid_ok(app_uid) and system_uid == app_uid:
        errors.append("deployment_target Namespace UIDs must be distinct")
    authorization = manifest.get("bootstrap_authorization")
    if isinstance(authorization, dict):
        for field in ("kube_context", "kubeconfig_sha256", "inventory_sha256", "namespace"):
            if target.get(field) != authorization.get(field):
                errors.append(f"deployment_target.{field} must match bootstrap_authorization.{field}")
    return errors


def _deployment_target_complete(manifest: dict[str, Any]) -> bool:
    if not _paperless_rke2_production(manifest):
        return True
    target = manifest.get("deployment_target")
    return bool(
        isinstance(target, dict)
        and _namespace_uid_ok(target.get("application_namespace_uid"))
        and not _deployment_target_errors(manifest)
    )


def _is_secret_bearing_key(value: str) -> bool:
    """Reject common secret-bearing field spellings without blocking identifiers."""
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return normalized in _SECRET_MANIFEST_KEYS or any(
        normalized.endswith(suffix) for suffix in _SECRET_MANIFEST_SUFFIXES
    )


def _is_absolute_uri(value: Any, *, allow_fragment: bool = True) -> bool:
    """Recognize an absolute URI without accepting whitespace or controls."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(char.isspace() or ord(char) < 0x20 for char in value)
    ):
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme and (allow_fragment or not parsed.fragment))


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timezone-qualified RFC 3339 timestamp without guessing a zone."""
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _is_real_timestamp(value: Any) -> bool:
    """Accept only timezone-qualified RFC 3339 timestamps for audit fields."""
    return _parse_timestamp(value) is not None


def _is_current_or_past_timestamp(
    value: Any, *, now: datetime | None = None
) -> bool:
    """Reject syntactically valid evidence timestamps placed in the future."""
    parsed = _parse_timestamp(value)
    current = now or datetime.now(timezone.utc)
    return parsed is not None and parsed <= current + APPROVAL_CLOCK_SKEW


def _evidence_max_age(
    freshness_policy: str,
    manifest: dict[str, Any],
) -> timedelta | None:
    """Return the bounded validity period for one evidence-record location."""

    limit = EVIDENCE_MAX_AGE_OVERRIDES.get(freshness_policy)
    if limit is None:
        section_name = freshness_policy.split(".", 1)[0].split("[", 1)[0]
        limit = EVIDENCE_MAX_AGE_BY_SECTION.get(section_name)
    if freshness_policy == "data_protection.backup" and limit is not None:
        data_protection = manifest.get("data_protection")
        rpo_minutes = (
            data_protection.get("rpo_minutes")
            if isinstance(data_protection, dict)
            else None
        )
        if type(rpo_minutes) is int and rpo_minutes > 0:
            limit = min(limit, timedelta(minutes=rpo_minutes))
    return limit


def _evidence_timestamp_is_fresh(
    value: Any,
    manifest: dict[str, Any],
    freshness_policy: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Require evidence to be current for its operational control domain."""

    parsed = _parse_timestamp(value)
    limit = _evidence_max_age(freshness_policy, manifest)
    current = now or datetime.now(timezone.utc)
    return bool(
        parsed is not None
        and limit is not None
        and parsed <= current + APPROVAL_CLOCK_SKEW
        and parsed >= current - limit - APPROVAL_CLOCK_SKEW
    )


def _freshness_window_label(limit: timedelta) -> str:
    seconds = int(limit.total_seconds())
    for unit, divisor in (
        ("day", 24 * 60 * 60),
        ("hour", 60 * 60),
        ("minute", 60),
    ):
        if seconds % divisor == 0:
            amount = seconds // divisor
            suffix = "" if amount == 1 else "s"
            return f"{amount} {unit}{suffix}"
    return f"{seconds} seconds"


def _approval_window_errors(
    section: Any,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Reject stale, excessively long, or implausibly future approvals."""
    if not isinstance(section, dict):
        return ["governance must be an object"]
    approved_at = _parse_timestamp(section.get("approved_at"))
    valid_until = _parse_timestamp(section.get("valid_until"))
    errors: list[str] = []
    if approved_at is None:
        errors.append(
            "governance.approved_at must be a timezone-qualified RFC 3339 timestamp"
        )
    if valid_until is None:
        errors.append(
            "governance.valid_until must be a timezone-qualified RFC 3339 timestamp"
        )
    if approved_at is None or valid_until is None:
        return errors
    current = now or datetime.now(timezone.utc)
    if approved_at > current + APPROVAL_CLOCK_SKEW:
        errors.append("governance.approved_at must not be future-dated")
    if valid_until <= approved_at:
        errors.append("governance.valid_until must be later than governance.approved_at")
    elif valid_until - approved_at > APPROVAL_MAX_VALIDITY:
        errors.append("governance approval validity must not exceed 30 days")
    if valid_until <= current:
        errors.append("governance approval has expired")
    return errors


def _relative_candidate(value: Any, root: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip() or PLACEHOLDER_RE.search(value):
        return None
    candidate = Path(value)
    if (
        candidate.is_absolute()
        or candidate.anchor
        or candidate.drive
        or WINDOWS_ABSOLUTE_RE.match(value)
        or "\\" in value
        or "\x00" in value
        or ".." in candidate.parts
    ):
        return None
    candidate_path = root / candidate
    if has_symlink_component(root) or has_symlink_component(candidate_path):
        return None
    try:
        current = root
        for part in candidate.parts:
            current = current / part
            if current.is_symlink():
                return None
    except OSError:
        return None
    try:
        root_resolved = root.resolve()
        evidence_resolved = candidate_path.resolve()
        evidence_resolved.relative_to(root_resolved)
    except (OSError, ValueError):
        return None
    try:
        if not evidence_resolved.is_file() or evidence_resolved.stat().st_size == 0:
            return None
    except OSError:
        return None
    return evidence_resolved


def _indexed_measure(
    candidate: Path | None,
    context: EvidenceContext | None,
) -> tuple[int, str] | None:
    if candidate is None or context is None:
        return None
    bundle_root, indexed_files, _ = context
    try:
        relative = candidate.relative_to(bundle_root).as_posix()
    except ValueError:
        return None
    expected = indexed_files.get(relative)
    if expected is None:
        return None
    try:
        measured = _measure_regular_file(candidate)
    except OSError:
        return None
    return measured if measured == expected else None


def _indexed(candidate: Path | None, context: EvidenceContext | None) -> bool:
    return _indexed_measure(candidate, context) is not None


def _indexed_bytes(
    candidate: Path | None,
    context: EvidenceContext | None,
) -> bytes | None:
    """Read exactly the bytes bound by the verified evidence index."""
    if candidate is None or context is None:
        return None
    bundle_root, indexed_files, _ = context
    try:
        relative = candidate.relative_to(bundle_root).as_posix()
    except ValueError:
        return None
    expected = indexed_files.get(relative)
    if expected is None or expected[0] > MAX_STRUCTURED_EVIDENCE_BYTES:
        return None
    try:
        content, digest = _read_stable_bytes(
            candidate,
            max_bytes=MAX_STRUCTURED_EVIDENCE_BYTES,
        )
    except OSError:
        return None
    return content if (len(content), digest) == expected else None


def _evidence_exists(value: Any, root: Path, context: EvidenceContext | None) -> bool:
    if not isinstance(value, dict) or value.get("status") != "pass":
        return False
    evidence = value.get("evidence")
    return _indexed(_relative_candidate(evidence, root), context)


def _evidence_metadata_matches(
    value: Any,
    manifest: dict[str, Any],
    *,
    freshness_policy: str | None = None,
) -> bool:
    if not isinstance(value, dict):
        return False
    release = manifest.get("release")
    service = manifest.get("service")
    release_version = release.get("version") if isinstance(release, dict) else None
    execution_environment = release.get("execution_environment") if isinstance(release, dict) else None
    execution_environment_digest = execution_environment.get("digest") if isinstance(execution_environment, dict) else None
    solution_id = service.get("solution_id") if isinstance(service, dict) else None
    runtime = service.get("runtime") if isinstance(service, dict) else None
    underlying_runtime = service.get("underlying_runtime") if isinstance(service, dict) else None
    os_id = service.get("os_id") if isinstance(service, dict) else None
    environment = service.get("environment") if isinstance(service, dict) else None
    return bool(
        _is_real_text(value.get("name"))
        and value.get("solution") == solution_id
        and value.get("runtime") == runtime
        and (runtime != "ansible" or value.get("underlying_runtime") == underlying_runtime)
        and value.get("os_id") == os_id
        and value.get("release") == release_version
        and value.get("environment") == environment
        and (
            freshness_policy == "release"
            or not _deployment_target_complete(manifest)
            or value.get("deployment_target") == manifest.get("deployment_target")
        )
        and (
            runtime != "ansible"
            or value.get("execution_environment_digest") == execution_environment_digest
        )
        and (
            (
                isinstance(value.get("execution_environment"), str)
                and value.get("execution_environment") in ENVIRONMENT_VALUES
            )
            or (
                freshness_policy == "release"
                and _has_structured_release_execution_environment(value)
            )
        )
        and (
            _is_current_or_past_timestamp(value.get("recorded_at"))
            if freshness_policy is None
            else _evidence_timestamp_is_fresh(
                value.get("recorded_at"), manifest, freshness_policy
            )
        )
        and _is_real_text(value.get("operator"))
        and _is_real_text(value.get("fixture_set"))
    )


def _evidence_payload_matches(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
    *,
    freshness_policy: str | None = None,
) -> bool:
    payload = _json_evidence_payload(value, root, context)
    if payload is None:
        return False
    return bool(
        payload.get("status") == "pass"
        and freshness_policy is not None
        and _evidence_outcome_matches(payload, manifest, freshness_policy)
        and isinstance(value, dict)
        and _json_contains(payload, value)
        and payload.get("name") == value.get("name")
        and payload.get("evidence") == value.get("evidence")
        and _evidence_metadata_matches(
            payload,
            manifest,
            freshness_policy=freshness_policy,
        )
    )


def _evidence_outcome_matches(
    payload: dict[str, Any], manifest: dict[str, Any], claim: str
) -> bool:
    """Require an indexed record to describe the particular passing claim."""
    release = manifest.get("release")
    source_revision = release.get("source_revision") if isinstance(release, dict) else None
    outcome = payload.get("outcome")
    if not (
        payload.get("claim") == claim
        and isinstance(source_revision, str)
        and GITHUB_SOURCE_REVISION_RE.fullmatch(source_revision)
        and payload.get("source_revision") == source_revision
        and isinstance(outcome, dict)
        and outcome.get("status") == "pass"
        and isinstance(outcome.get("method"), str)
        and outcome.get("method") in {"automated", "manual"}
        and _is_real_text(outcome.get("summary"))
        and _is_real_text(outcome.get("source"))
        and _is_absolute_uri(outcome.get("source"))
    ):
        return False
    if outcome.get("method") == "manual":
        reviewer = outcome.get("reviewed_by")
        if not (
            _is_real_text(reviewer)
            and isinstance(reviewer, str)
            and reviewer.strip().casefold()
            != str(payload.get("operator", "")).strip().casefold()
        ):
            return False
    return _recorded_returncodes_pass(payload)


def _recorded_returncodes_pass(payload: dict[str, Any]) -> bool:
    """Reject failed command results even when embedded below a summary."""
    pending: list[Any] = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                field = key.casefold()
                if field == "rc" or field.endswith("returncode"):
                    if type(item) is not int or item != 0:
                        return False
                else:
                    pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return True


def _json_contains(actual: Any, expected: Any) -> bool:
    """Require every manifest claim to be represented identically in evidence."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _json_contains(actual[key], expected_value)
            for key, expected_value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(
                _json_contains(actual_value, expected_value)
                for actual_value, expected_value in zip(actual, expected)
            )
        )
    return type(actual) is type(expected) and actual == expected


def _json_evidence_payload(value: Any, root: Path, context: EvidenceContext | None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    candidate = _relative_candidate(value.get("evidence"), root)
    if candidate is None or candidate.suffix.lower() != ".json":
        return None
    content = _indexed_bytes(candidate, context)
    if content is None:
        return None
    try:
        payload = load_json_document(content.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return (
        payload
        if isinstance(payload, dict)
        and not _json_shape_errors(
            payload,
            "evidence JSON",
            max_nodes=MAX_EVIDENCE_JSON_NODES,
        )
        else None
    )


def _evidence_record_exists(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
    *,
    freshness_policy: str,
) -> bool:
    evidence_is_valid = (
        _evidence_exists(value, root, context)
        and _evidence_metadata_matches(
            value,
            manifest,
            freshness_policy=freshness_policy,
        )
        and _evidence_payload_matches(
            value,
            root,
            context,
            manifest,
            freshness_policy=freshness_policy,
        )
    )
    if not evidence_is_valid:
        return False
    if not _operational_run_receipt_required(manifest, freshness_policy):
        return True
    return _operational_run_receipt_ok(
        value,
        root,
        context,
        manifest,
        freshness_policy=freshness_policy,
    )


def _operational_run_receipt_required(
    manifest: dict[str, Any], claim: str
) -> bool:
    return bool(
        _paperless_rke2_production(manifest)
        and _deployment_target_complete(manifest)
        and claim != "release"
        and not claim.startswith("release.")
    )


def _operational_run_receipt_ok(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
    *,
    freshness_policy: str,
) -> bool:
    """Require independent, signed execution evidence for a production claim."""
    if not isinstance(value, dict):
        return False
    reference = value.get("run_receipt")
    hook = value.get("run_hook")
    if (
        not isinstance(reference, dict)
        or set(reference) != {"path", "signature", "signer"}
        or not _is_real_text(reference.get("signer"))
        or not isinstance(hook, dict)
        or set(hook) != {"executable_sha256", "argv_sha256"}
        or any(
            not isinstance(hook.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", hook[field]) is None
            for field in ("executable_sha256", "argv_sha256")
        )
    ):
        return False
    receipt_path = _relative_candidate(reference.get("path"), root)
    signature_path = _relative_candidate(reference.get("signature"), root)
    receipt_bytes = _indexed_bytes(receipt_path, context)
    if receipt_bytes is None or signature_path is None:
        return False
    try:
        receipt = load_json_document(receipt_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "claim",
        "status",
        "service",
        "release_version",
        "source_revision",
        "execution_environment_digest",
        "deployment_target",
        "run_id",
        "started_at",
        "completed_at",
        "hook",
        "returncode",
        "evidence_sha256",
        "runner",
    }:
        return False
    release = manifest.get("release")
    service = manifest.get("service")
    deployment_target = manifest.get("deployment_target")
    execution_environment = (
        release.get("execution_environment") if isinstance(release, dict) else None
    )
    runner = receipt.get("runner")
    expected_service_fields = {
        "solution_id",
        "runtime",
        "underlying_runtime",
        "os_id",
        "environment",
    }
    service_identity = (
        {key: service.get(key) for key in expected_service_fields}
        if isinstance(service, dict)
        else None
    )
    start = _parse_timestamp(receipt.get("started_at"))
    finish = _parse_timestamp(receipt.get("completed_at"))
    current = datetime.now(timezone.utc)
    recorded_at = _parse_timestamp(value.get("recorded_at"))
    hook_record = receipt.get("hook")
    if (
        type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 2
        or receipt.get("claim") != freshness_policy
        or receipt.get("status") != "pass"
        or not isinstance(service, dict)
        or not isinstance(receipt.get("service"), dict)
        or set(receipt["service"]) != expected_service_fields
        or receipt.get("service") != service_identity
        or not isinstance(release, dict)
        or receipt.get("release_version") != release.get("version")
        or receipt.get("source_revision") != release.get("source_revision")
        or not isinstance(execution_environment, dict)
        or receipt.get("execution_environment_digest") != execution_environment.get("digest")
        or not isinstance(deployment_target, dict)
        or not _deployment_target_complete(manifest)
        or receipt.get("deployment_target") != deployment_target
        or not isinstance(receipt.get("run_id"), str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            receipt["run_id"],
        )
        is None
        or start is None
        or finish is None
        or start > finish
        or finish > current + APPROVAL_CLOCK_SKEW
        or finish - start > timedelta(days=7)
        or recorded_at is None
        or finish > recorded_at + APPROVAL_CLOCK_SKEW
        or recorded_at - finish > APPROVAL_CLOCK_SKEW
        or not _evidence_timestamp_is_fresh(receipt.get("completed_at"), manifest, freshness_policy)
        or hook_record != hook
        or type(receipt.get("returncode")) is not int
        or receipt.get("returncode") != 0
        or not isinstance(value.get("evidence"), str)
        or receipt.get("evidence_sha256")
        != "sha256:" + hashlib.sha256(_indexed_bytes(_relative_candidate(value["evidence"], root), context) or b"").hexdigest()
        or not isinstance(runner, dict)
        or set(runner) != {"name", "image", "digest"}
        or runner.get("name") != reference.get("signer")
        or not isinstance(runner.get("image"), str)
        or not isinstance(runner.get("digest"), str)
        or not runner["image"].endswith("@" + runner["digest"])
        or re.fullmatch(r"sha256:[0-9a-f]{64}", runner["digest"]) is None
    ):
        return False
    signer = _approved_signer(
        manifest,
        "operational-evidence",
        runner.get("name"),
        runner.get("digest"),
        image=runner.get("image"),
    )
    if signer is None:
        return False
    identity, issuer = signer
    return bool(
        _sigstore_bundle_binds_content(reference.get("signature"), receipt_bytes, root, context)
        and _verify_sigstore_bundle(
            reference.get("signature"),
            receipt_bytes,
            identity,
            issuer,
            root,
            context,
        )
    )


def _relative_file(value: Any, root: Path, context: EvidenceContext | None) -> bool:
    # A referenced artifact, detached signature, or runbook must contain
    # content; an indexed zero-byte placeholder is not operational proof.
    candidate = _relative_candidate(value, root)
    measured = _indexed_measure(candidate, context)
    return measured is not None and measured[0] > 0


def _path_identity(value: Any) -> str | None:
    """Return a normalized relative spelling for cross-field path checks."""
    if not isinstance(value, str) or not value.strip():
        return None
    return os.path.normcase(Path(value).as_posix())


def _artifact_proof_paths(value: Any) -> set[str]:
    """Return every proof path associated with one artifact."""
    return set(_artifact_proof_path_entries(value))


def _artifact_core_proof_paths(value: Any) -> set[str]:
    """Return the three primary paths required for one artifact."""
    if not isinstance(value, dict):
        return set()
    paths = {
        _path_identity(value.get(field))
        for field in ("path", "sbom", "signature")
    }
    return {path for path in paths if path is not None}


def _artifact_proof_path_entries(value: Any) -> list[str]:
    """Return every indexed path used to prove one artifact."""
    if not isinstance(value, dict):
        return []
    paths = [
        _path_identity(value.get(field))
        for field in ("path", "sbom", "signature", "provenance", "provenance_bundle")
    ]
    for field in ("signature_verification", "verification"):
        verification = value.get(field)
        if isinstance(verification, dict):
            paths.append(_path_identity(verification.get("evidence")))
    return [path for path in paths if path is not None]


def _execution_environment_proof_paths(value: Any) -> set[str]:
    """Return every proof path associated with the controller image."""
    return set(_execution_environment_proof_path_entries(value))


def _execution_environment_core_proof_paths(value: Any) -> set[str]:
    """Return the three primary paths required for the controller image."""
    if not isinstance(value, dict):
        return set()
    paths = {
        _path_identity(value.get(field))
        for field in ("provenance", "sbom", "signature")
    }
    return {path for path in paths if path is not None}


def _execution_environment_proof_path_entries(value: Any) -> list[str]:
    """Return every indexed path used to prove the controller image."""
    if not isinstance(value, dict):
        return []
    paths = [
        _path_identity(value.get(field))
        for field in ("provenance", "sbom", "signature")
    ]
    verification = value.get("signature_verification")
    if isinstance(verification, dict):
        paths.append(_path_identity(verification.get("evidence")))
    return [path for path in paths if path is not None]


def _github_controls_proof_paths(value: Any) -> set[str]:
    return set(_github_controls_proof_path_entries(value))


def _github_controls_proof_path_entries(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    paths = [_path_identity(value.get(field)) for field in ("path", "signature")]
    signature_verification = value.get("signature_verification")
    if isinstance(signature_verification, dict):
        paths.append(_path_identity(signature_verification.get("evidence")))
    return [path for path in paths if path is not None]


def _release_proof_paths(value: Any) -> set[str]:
    """Return every local proof path owned by a release section."""
    return set(_release_proof_path_entries(value))


def _release_proof_path_entries(value: Any) -> list[str]:
    """Return every local proof path owned by a release section."""
    if not isinstance(value, dict):
        return []
    paths: list[str] = []
    for field in ("evidence", "provenance", "provenance_bundle"):
        path = _path_identity(value.get(field))
        if path is not None:
            paths.append(path)
    artifacts = value.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            paths.extend(_artifact_proof_path_entries(artifact))
    paths.extend(_artifact_proof_path_entries(value.get("provider_bundle")))
    paths.extend(
        _execution_environment_proof_path_entries(value.get("execution_environment"))
    )
    paths.extend(_github_controls_proof_path_entries(value.get("github_controls")))
    return paths


def _release_proof_names(value: Any) -> set[str]:
    """Return normalized artifact identities owned by a release section."""
    return set(_release_proof_name_entries(value))


def _release_proof_name_entries(value: Any) -> list[str]:
    """Return every normalized artifact identity owned by a release section."""
    if not isinstance(value, dict):
        return []
    names: list[str] = []
    artifacts = value.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if isinstance(artifact, dict) and _is_real_text(artifact.get("name")):
                names.append(str(artifact["name"]).casefold())
    for field in ("provider_bundle", "execution_environment"):
        item = value.get(field)
        if isinstance(item, dict) and _is_real_text(item.get("name")):
            names.append(str(item["name"]).casefold())
    return names


def _structured_json_payload(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    required_groups: tuple[tuple[str, ...], ...],
) -> dict[str, Any] | None:
    """Require an indexed JSON attestation with meaningful grouped content."""
    candidate = _relative_candidate(value, root)
    if candidate is None or candidate.suffix.lower() != ".json":
        return None
    content = _indexed_bytes(candidate, context)
    if content is None:
        return None
    try:
        payload = load_json_document(content.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if _json_shape_errors(
        payload,
        "structured evidence JSON",
        max_nodes=MAX_EVIDENCE_JSON_NODES,
    ):
        return None

    def meaningful_group(key: str) -> bool:
        item = payload.get(key)
        if key == "subject":
            return isinstance(item, list) and any(
                isinstance(subject, dict) and _is_real_text(subject.get("name"))
                for subject in item
            )
        if key in {"packages", "components"}:
            identity_keys = (
                "name",
                "SPDXID",
                "bom-ref",
                "purl",
                "group",
            )
            return isinstance(item, list) and any(
                isinstance(component, dict)
                and any(_is_real_text(component.get(identity)) for identity in identity_keys)
                for component in item
            )
        if isinstance(item, str):
            return _is_real_text(item)
        if isinstance(item, list):
            return bool(item) and any(isinstance(child, (dict, str)) and bool(child) for child in item)
        return isinstance(item, dict) and bool(item)

    if not all(
        any(meaningful_group(key) for key in group)
        for group in required_groups
    ):
        return None
    return payload


def _github_controls_errors(
    value: Any,
    expected_repository: Any,
    expected_repository_id: Any,
    expected_source_revision: Any,
    manifest: dict[str, Any],
    root: Path,
    context: EvidenceContext | None,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Validate a fresh, indexed hosted-control audit bound to this source."""
    if not isinstance(value, dict):
        return ["must be a signed hosted-control audit reference"]
    errors: list[str] = []
    if set(value) != GITHUB_AUDIT_REFERENCE_FIELDS:
        errors.append("reference must contain exactly the signed-audit fields")
    candidate = _relative_candidate(value.get("path"), root)
    if candidate is None or candidate.suffix.lower() != ".json":
        errors.append("path must identify an indexed JSON report inside the evidence bundle")
        return errors
    content = _indexed_bytes(candidate, context)
    if content is None:
        errors.append("report must be present with matching bytes in the verified evidence index")
        return errors
    digest = value.get("digest")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        or f"sha256:{hashlib.sha256(content).hexdigest()}" != digest
    ):
        errors.append("digest must match the indexed report bytes")
    signing_policy = _signing_policy(manifest)
    certificate_identity = _github_release_certificate_identity(
        expected_repository,
        signing_policy.get("github_controls_identity")
        if isinstance(signing_policy, dict) else None,
    )
    if (
        certificate_identity is None
        or not _sigstore_bundle_binds_content(
            value.get("signature"), content, root, context
        )
        or not _verify_sigstore_bundle(
            value.get("signature"), content, certificate_identity,
            SIGSTORE_GITHUB_OIDC_ISSUER, root, context
        )
    ):
        errors.append(
            "signature must be an indexed, cryptographically verified Sigstore v0.3 "
            "keyless bundle bound to the report and release workflow identity"
        )
    if value.get("signature_verified") is not True:
        errors.append("signature_verified must be true")
    verification = value.get("signature_verification")
    verification_payload = _json_evidence_payload(verification, root, context)
    if (
        not _evidence_record_exists(
            verification,
            root,
            context,
            manifest,
            freshness_policy="release",
        )
        or not isinstance(verification_payload, dict)
        or verification_payload.get("artifact_digest") != digest
        or not _is_real_text(verification_payload.get("verifier"))
    ):
        errors.append(
            "signature_verification must be indexed evidence bound to the report digest"
        )
    try:
        payload = load_json_document(content.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append("report must contain unambiguous UTF-8 JSON")
        return errors
    if not isinstance(payload, dict):
        errors.append("report must contain a JSON object")
        return errors

    payload_fields = set(payload)
    if payload_fields != GITHUB_AUDIT_TOP_LEVEL_FIELDS:
        errors.append("must contain exactly the production-control audit schema fields")
    if payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if payload.get("api_version") != GITHUB_AUDIT_API_VERSION:
        errors.append(f"api_version must be {GITHUB_AUDIT_API_VERSION}")

    repository = payload.get("repository")
    if (
        not isinstance(expected_repository, str)
        or GITHUB_REPOSITORY_RE.fullmatch(expected_repository) is None
        or not isinstance(repository, str)
        or GITHUB_REPOSITORY_RE.fullmatch(repository) is None
        or repository.casefold() != expected_repository.casefold()
    ):
        errors.append("repository must match release.source_repository")

    repository_id = payload.get("repository_id")
    if (
        isinstance(expected_repository_id, bool)
        or not isinstance(expected_repository_id, int)
        or expected_repository_id <= 0
        or isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or repository_id != expected_repository_id
    ):
        errors.append("repository_id must match release.source_repository_id")
    if not _is_real_text(payload.get("repository_node_id")):
        errors.append("repository_node_id must identify the authoritative GitHub repository")

    source_revision = payload.get("source_revision")
    if (
        not isinstance(expected_source_revision, str)
        or GITHUB_SOURCE_REVISION_RE.fullmatch(expected_source_revision) is None
        or source_revision != expected_source_revision
    ):
        errors.append("source_revision must match release.source_revision")

    audited_at = _parse_timestamp(payload.get("audited_at"))
    current = now or datetime.now(timezone.utc)
    if audited_at is None:
        errors.append("audited_at must be a timezone-qualified RFC 3339 timestamp")
    elif audited_at > current + APPROVAL_CLOCK_SKEW:
        errors.append("audited_at must not be future-dated")
    elif audited_at < current - GITHUB_AUDIT_MAX_AGE:
        errors.append("audit must be no more than 24 hours old")

    if payload.get("passed") is not True:
        errors.append("passed must be true")
    controls = payload.get("controls")
    if not isinstance(controls, list) or len(controls) != len(GITHUB_AUDIT_CONTROL_NAMES):
        errors.append("controls must contain exactly the 12 required hosted controls")
        return errors
    names: list[str] = []
    controls_valid = True
    for control in controls:
        if (
            not isinstance(control, dict)
            or set(control) != GITHUB_AUDIT_CONTROL_FIELDS
            or not isinstance(control.get("name"), str)
            or control.get("passed") is not True
            or not _is_real_text(control.get("detail"))
        ):
            controls_valid = False
            continue
        names.append(control["name"])
    if (
        not controls_valid
        or len(names) != len(controls)
        or len(set(names)) != len(names)
        or set(names) != GITHUB_AUDIT_CONTROL_NAMES
    ):
        errors.append(
            "controls must be unique, exact-schema records with every required control passing"
        )
    return errors


def _decoded_base64(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded or None


def _github_release_certificate_identity(repository: Any, identity: Any) -> str | None:
    """Accept only a controller-approved tagged release workflow identity."""
    if (
        not isinstance(repository, str)
        or GITHUB_REPOSITORY_RE.fullmatch(repository) is None
        or not isinstance(identity, str)
    ):
        return None
    prefix = (
        f"https://github.com/{repository}/.github/workflows/release.yml"
        "@refs/tags/v"
    )
    tag = identity[len(prefix):] if identity.startswith(prefix) else ""
    return identity if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag) else None


def _trusted_cosign_binary() -> Path | None:
    """Require a controller-pinned executable, never a lookup through PATH."""
    return _controller_pinned_file(
        "ARCHIVEWEAVER_COSIGN_PATH",
        "ARCHIVEWEAVER_COSIGN_SHA256",
        MAX_COSIGN_BINARY_BYTES,
        "Cosign verifier",
    )


def _controller_pinned_file(
    path_variable: str,
    digest_variable: str,
    max_bytes: int,
    label: str,
) -> Path | None:
    """Resolve one controller-owned file by absolute path and approved digest."""
    binary_value = os.environ.get(path_variable)
    digest_value = os.environ.get(digest_variable)
    if (
        not isinstance(binary_value, str)
        or not binary_value
        or not isinstance(digest_value, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest_value) is None
    ):
        return None
    binary = Path(binary_value)
    if not binary.is_absolute() or has_symlink_component(binary):
        return None
    try:
        size, digest = _measure_regular_file(
            binary,
            max_bytes=max_bytes,
            label=label,
        )
    except OSError:
        return None
    return binary if size > 0 and digest == digest_value else None


def _trusted_file_bytes(
    path_variable: str,
    digest_variable: str,
    max_bytes: int,
    label: str,
) -> bytes | None:
    candidate = _controller_pinned_file(
        path_variable, digest_variable, max_bytes, label
    )
    if candidate is None:
        return None
    try:
        content, digest = _read_stable_bytes(candidate, max_bytes=max_bytes)
    except OSError:
        return None
    return content if digest == os.environ.get(digest_variable) else None


def _signer_text(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and value == value.strip()
        and not PLACEHOLDER_RE.search(value)
        and not any(character.isspace() or ord(character) < 32 for character in value)
        and "*" not in value
    )


def _oci_release_image_ref_ok(value: Any) -> bool:
    """Accept only canonical digest refs with an explicit registry host."""
    if not isinstance(value, str) or OCI_RELEASE_IMAGE_RE.fullmatch(value) is None:
        return False
    registry = value.split("/", 1)[0]
    hostname, separator, port = registry.partition(":")
    if separator and (not port or len(port) > 5 or int(port) > 65535):
        return False
    labels = hostname.split(".")
    if not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return False
    return bool(hostname == "localhost" or len(labels) > 1 or separator)


def _signing_policy(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Read a digest-pinned signer policy outside the manifest/evidence bundle."""
    content = _trusted_file_bytes(
        "ARCHIVEWEAVER_SIGNING_POLICY_PATH",
        "ARCHIVEWEAVER_SIGNING_POLICY_SHA256",
        MAX_SIGNING_POLICY_BYTES,
        "signing policy",
    )
    if content is None:
        return None
    try:
        policy = load_json_document(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        return None
    release = manifest.get("release")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"schema_version", "release_version", "source_repository", "github_controls_identity", "signers"}
        or type(policy.get("schema_version")) is not int
        or policy.get("schema_version") != 1
        or not isinstance(release, dict)
        or policy.get("release_version") != release.get("version")
        or policy.get("source_repository") != release.get("source_repository")
        or _github_release_certificate_identity(
            policy.get("source_repository"), policy.get("github_controls_identity")
        ) is None
        or not isinstance(policy.get("signers"), list)
    ):
        return None
    seen: set[tuple[str, str]] = set()
    for signer in policy["signers"]:
        if not isinstance(signer, dict):
            return None
        role = signer.get("role")
        expected_fields = {"role", "name", "digest", "identity", "issuer"}
        has_image = role in {"execution-environment", "operational-evidence"} or (
            role == "release-artifact" and "image" in signer
        )
        if has_image:
            expected_fields.add("image")
        if role == "rollback-artifact":
            expected_fields.add("release_version")
        if (
            not isinstance(role, str)
            or role not in SIGNING_ROLES
            or set(signer) != expected_fields
            or not _is_real_text(signer.get("name"))
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(signer.get("digest", ""))) is None
            or not _signer_text(signer.get("identity"))
            or not _signer_text(signer.get("issuer"))
            or (role == "rollback-artifact" and not _is_real_text(signer.get("release_version")))
        ):
            return None
        try:
            issuer = urlparse(signer["issuer"])
        except ValueError:
            return None
        if (
            issuer.scheme != "https"
            or not issuer.netloc
            or issuer.username is not None
            or issuer.password is not None
            or issuer.query
            or issuer.fragment
        ):
            return None
        if has_image and (
            not isinstance(signer.get("image"), str)
            or (
                OCI_IMAGE_DIGEST_RE.fullmatch(signer["image"]) is None
                if role in {"execution-environment", "operational-evidence"}
                else not _oci_release_image_ref_ok(signer["image"])
            )
            or not signer["image"].endswith("@" + signer["digest"])
        ):
            return None
        key = (role, signer["name"])
        if key in seen:
            return None
        seen.add(key)
    return policy


def _approved_signer(
    manifest: dict[str, Any],
    role: str,
    name: Any,
    digest: Any,
    *,
    image: Any = None,
    release_version: Any = None,
) -> tuple[str, str] | None:
    policy = _signing_policy(manifest)
    if policy is None:
        return None
    for signer in policy["signers"]:
        if (
            signer["role"] == role
            and signer["name"] == name
            and signer["digest"] == digest
            and signer.get("image") == image
            and (role != "rollback-artifact" or signer.get("release_version") == release_version)
        ):
            return signer["identity"], signer["issuer"]
    return None


def _verify_sigstore_bundle(
    value: Any,
    signed_content: bytes | Path,
    certificate_identity: str,
    certificate_issuer: str,
    root: Path,
    context: EvidenceContext | None,
    *,
    attestation: bool = False,
) -> bool:
    """Verify indexed bytes with the controller's digest-pinned Cosign client."""
    candidate = _relative_candidate(value, root)
    bundle_content = _indexed_bytes(candidate, context)
    binary = _trusted_cosign_binary()
    trusted_root = _trusted_file_bytes(
        "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_PATH",
        "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_SHA256",
        MAX_SIGSTORE_TRUSTED_ROOT_BYTES,
        "Sigstore trusted root",
    )
    if bundle_content is None or binary is None or trusted_root is None:
        return False
    # Cosign reads private copies of the bundle and trusted root. Indexed
    # artifact files are checked before and after verification.
    try:
        with tempfile.TemporaryDirectory(prefix="archiveweaver-sigstore-") as scratch:
            report_path = Path(scratch) / "report.bin"
            bundle_path = Path(scratch) / "report.sigstore.json"
            trusted_root_path = Path(scratch) / "trusted-root.json"
            if isinstance(signed_content, bytes):
                report_path.write_bytes(signed_content)
            else:
                if _indexed_measure(signed_content, context) is None:
                    return False
                report_path = signed_content
            bundle_path.write_bytes(bundle_content)
            trusted_root_path.write_bytes(trusted_root)
            environment = {
                key: item
                for key, item in os.environ.items()
                if not key.startswith(("COSIGN_", "SIGSTORE_"))
            }
            command = [
                str(binary),
                "verify-blob-attestation" if attestation else "verify-blob",
                str(report_path),
                "--offline",
                "--bundle",
                str(bundle_path),
                "--trusted-root",
                str(trusted_root_path),
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                certificate_issuer,
            ]
            if attestation:
                command.append("--new-bundle-format")
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                check=False,
                timeout=60,
            )
            return bool(
                result.returncode == 0
                and _trusted_cosign_binary() == binary
                and _indexed_bytes(candidate, context) == bundle_content
                and (
                    not isinstance(signed_content, Path)
                    or _indexed_measure(signed_content, context) is not None
                )
            )
    except (OSError, subprocess.TimeoutExpired):
        return False


def _sigstore_bundle_binds_content(
    value: Any,
    signed_content: bytes,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Validate the canonical structure and embedded digest of a small blob."""
    return _sigstore_bundle_binds_digest(
        value, hashlib.sha256(signed_content).hexdigest(), root, context
    )


def _sigstore_bundle_binds_digest(
    value: Any,
    expected_sha256: str,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Validate bundle shape and digest before invoking the actual verifier."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        return False
    candidate = _relative_candidate(value, root)
    if candidate is None or not candidate.name.endswith(".sigstore.json"):
        return False
    content = _indexed_bytes(candidate, context)
    if content is None:
        return False
    try:
        payload = load_json_document(content.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    if not isinstance(payload, dict) or set(payload) != {
        "mediaType",
        "verificationMaterial",
        "messageSignature",
    }:
        return False
    if payload.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        return False
    verification_material = payload.get("verificationMaterial")
    if not isinstance(verification_material, dict):
        return False
    certificate = verification_material.get("certificate")
    if (
        not isinstance(certificate, dict)
        or _decoded_base64(certificate.get("rawBytes")) is None
    ):
        return False
    transparency_entries = verification_material.get("tlogEntries")
    if not isinstance(transparency_entries, list) or not transparency_entries:
        return False
    if not all(
        isinstance(entry, dict)
        and _decoded_base64(entry.get("canonicalizedBody")) is not None
        for entry in transparency_entries
    ):
        return False
    message_signature = payload.get("messageSignature")
    if not isinstance(message_signature, dict):
        return False
    message_digest = message_signature.get("messageDigest")
    if (
        not isinstance(message_digest, dict)
        or message_digest.get("algorithm") != "SHA2_256"
        or _decoded_base64(message_digest.get("digest"))
        != bytes.fromhex(expected_sha256)
        or _decoded_base64(message_signature.get("signature")) is None
    ):
        return False
    return True


def _github_controls_ok(
    release: dict[str, Any],
    manifest: dict[str, Any],
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    return not _github_controls_errors(
        release.get("github_controls"),
        release.get("source_repository"),
        release.get("source_repository_id"),
        release.get("source_revision"),
        manifest,
        root,
        context,
    )


def _spdx_packages(payload: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    """Return a validated SPDX 2.3 package map for the readiness profile."""
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        return None
    result: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            return None
        identifier = package.get("SPDXID")
        if (
            not isinstance(identifier, str)
            or not SPDX_ID_RE.fullmatch(identifier)
            or identifier in result
            or not isinstance(package.get("name"), str)
            or not package["name"].strip()
            or not isinstance(package.get("downloadLocation"), str)
            or not package["downloadLocation"].strip()
        ):
            return None
        files_analyzed = package.get("filesAnalyzed")
        if files_analyzed is not None and type(files_analyzed) is not bool:
            return None
        result[identifier] = package
    return result


def _spdx_sbom_valid(payload: dict[str, Any]) -> bool:
    """Enforce the SPDX 2.3 document and described-package trust boundary."""
    creation = payload.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, dict) else None
    created = creation.get("created") if isinstance(creation, dict) else None
    packages = _spdx_packages(payload)
    described = payload.get("documentDescribes")
    return bool(
        payload.get("spdxVersion") == SPDX_VERSION
        and payload.get("dataLicense") == "CC0-1.0"
        and payload.get("SPDXID") == "SPDXRef-DOCUMENT"
        and isinstance(payload.get("name"), str)
        and bool(payload["name"].strip())
        and _is_absolute_uri(payload.get("documentNamespace"), allow_fragment=False)
        and isinstance(created, str)
        and SPDX_CREATED_RE.fullmatch(created)
        and _parse_timestamp(created) is not None
        and isinstance(creators, list)
        and bool(creators)
        and all(
            isinstance(creator, str) and SPDX_CREATOR_RE.match(creator)
            for creator in creators
        )
        and packages is not None
        and isinstance(described, list)
        and bool(described)
        and all(isinstance(identifier, str) for identifier in described)
        and len(described) == len(set(described))
        and all(identifier in packages for identifier in described)
    )


def _cyclonedx_component_valid(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and isinstance(value.get("type"), str)
        and value.get("type") in CYCLONEDX_COMPONENT_TYPES
        and isinstance(value.get("name"), str)
        and bool(value["name"].strip())
        and (
            "bom-ref" not in value
            or (isinstance(value.get("bom-ref"), str) and bool(value["bom-ref"].strip()))
        )
    )


def _cyclonedx_sbom_valid(payload: dict[str, Any]) -> bool:
    """Enforce an auditable CycloneDX 1.6/1.7 production SBOM profile."""
    spec_version = payload.get("specVersion")
    metadata = payload.get("metadata")
    components = payload.get("components")
    schema = payload.get("$schema")
    expected_schemas = (
        {
            f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
            f"https://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        }
        if isinstance(spec_version, str)
        else set()
    )
    component_refs = [
        component.get("bom-ref")
        for component in components
        if isinstance(component, dict) and isinstance(component.get("bom-ref"), str)
    ] if isinstance(components, list) else []
    return bool(
        payload.get("bomFormat") == "CycloneDX"
        and isinstance(spec_version, str)
        and spec_version in SUPPORTED_CYCLONEDX_VERSIONS
        and isinstance(schema, str)
        and schema in expected_schemas
        and isinstance(payload.get("serialNumber"), str)
        and CYCLONEDX_SERIAL_RE.fullmatch(payload["serialNumber"])
        and type(payload.get("version")) is int
        and payload["version"] >= 1
        and isinstance(metadata, dict)
        and _parse_timestamp(metadata.get("timestamp")) is not None
        and _cyclonedx_component_valid(metadata.get("component"))
        and isinstance(components, list)
        and bool(components)
        and all(_cyclonedx_component_valid(component) for component in components)
        and len(component_refs) == len(set(component_refs))
    )


def _sbom_payload(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
) -> dict[str, Any] | None:
    payload = _structured_json_payload(value, root, context, SBOM_GROUPS)
    if payload is None:
        return None
    if _spdx_sbom_valid(payload):
        return payload
    if _cyclonedx_sbom_valid(payload):
        return payload
    return None


def _sbom_binds_name(
    value: Any,
    expected_name: str,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Require the SBOM to identify the artifact it is attached to."""
    payload = _sbom_payload(value, root, context)
    if payload is None or not _is_real_text(expected_name):
        return False
    if payload.get("spdxVersion") == SPDX_VERSION:
        packages = _spdx_packages(payload)
        described = payload.get("documentDescribes")
        return bool(
            packages is not None
            and isinstance(described, list)
            and any(packages[identifier].get("name") == expected_name for identifier in described)
        )
    metadata = payload.get("metadata")
    subject = metadata.get("component") if isinstance(metadata, dict) else None
    return bool(isinstance(subject, dict) and subject.get("name") == expected_name)


def _sbom_binds_named_sha256(
    value: Any,
    expected_name: str,
    digest: str,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Bind an OCI image to the described SBOM subject, not a dependency."""
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        return False
    payload = _sbom_payload(value, root, context)
    if payload is None:
        return False
    expected_hash = digest.removeprefix("sha256:")
    if payload.get("spdxVersion") == SPDX_VERSION:
        packages = _spdx_packages(payload)
        described = payload.get("documentDescribes")
        if packages is None or not isinstance(described, list):
            return False
        subjects = (packages[identifier] for identifier in described)
        for subject in subjects:
            checksums = subject.get("checksums")
            if subject.get("name") == expected_name and isinstance(checksums, list) and any(
                isinstance(checksum, dict)
                and checksum.get("algorithm") == "SHA256"
                and checksum.get("checksumValue") == expected_hash
                for checksum in checksums
            ):
                return True
        return False
    metadata = payload.get("metadata")
    metadata_subject = metadata.get("component") if isinstance(metadata, dict) else None
    hashes = metadata_subject.get("hashes") if isinstance(metadata_subject, dict) else None
    return bool(
        isinstance(metadata_subject, dict)
        and metadata_subject.get("name") == expected_name
        and isinstance(hashes, list)
        and any(
            isinstance(item, dict)
            and item.get("alg") == "SHA-256"
            and item.get("content") == expected_hash
            for item in hashes
        )
    )


def _provenance_payload(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
) -> dict[str, Any] | None:
    payload = _structured_json_payload(value, root, context, PROVENANCE_GROUPS)
    if payload is None:
        return None
    statement_type = payload.get("_type", payload.get("type"))
    subjects = payload.get("subject")
    predicate = payload.get("predicate")
    build_definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    subject_names: list[str] = []
    if isinstance(subjects, list):
        subject_names = [
            str(subject.get("name"))
            for subject in subjects
            if isinstance(subject, dict) and isinstance(subject.get("name"), str)
        ]
    if not (
        statement_type == IN_TOTO_STATEMENT_TYPE
        and payload.get("predicateType") == SLSA_PROVENANCE_TYPE
        and isinstance(subjects, list)
        and bool(subjects)
        and len(subject_names) == len(subjects)
        and len(subject_names) == len(set(subject_names))
        and all(
            _is_real_text(subject.get("name"))
            and isinstance(subject.get("digest"), dict)
            and isinstance(subject["digest"].get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", subject["digest"]["sha256"])
            for subject in subjects
            if isinstance(subject, dict)
        )
        and isinstance(predicate, dict)
        and isinstance(build_definition, dict)
        and _is_absolute_uri(build_definition.get("buildType"))
        and isinstance(build_definition.get("externalParameters"), dict)
        and isinstance(run_details, dict)
        and isinstance(builder, dict)
        and _is_absolute_uri(builder.get("id"))
    ):
        return None
    return payload


def _indexed_dsse_statement_ok(
    statement_value: Any,
    bundle_value: Any,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Require the exact indexed statement bytes inside a Sigstore DSSE bundle."""
    statement_path = _relative_candidate(statement_value, root)
    bundle_path = _relative_candidate(bundle_value, root)
    statement_bytes = _indexed_bytes(statement_path, context)
    bundle_bytes = _indexed_bytes(bundle_path, context)
    if (
        statement_path is None
        or bundle_path is None
        or not bundle_path.name.endswith(".sigstore.json")
        or statement_path == bundle_path
        or statement_bytes is None
        or bundle_bytes is None
    ):
        return False
    try:
        bundle = load_json_document(bundle_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(bundle, dict) or set(bundle) != {
        "mediaType",
        "verificationMaterial",
        "dsseEnvelope",
    }:
        return False
    verification_material = bundle.get("verificationMaterial")
    envelope = bundle.get("dsseEnvelope")
    if (
        bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE
        or not isinstance(verification_material, dict)
        or not isinstance(verification_material.get("certificate"), dict)
        or _decoded_base64(
            verification_material["certificate"].get("rawBytes")
        ) is None
        or not isinstance(verification_material.get("tlogEntries"), list)
        or not verification_material["tlogEntries"]
        or not all(
            isinstance(item, dict)
            and _decoded_base64(item.get("canonicalizedBody")) is not None
            for item in verification_material["tlogEntries"]
        )
        or not isinstance(envelope, dict)
        or envelope.get("payloadType") != "application/vnd.in-toto+json"
        or _decoded_base64(envelope.get("payload")) != statement_bytes
        or not isinstance(envelope.get("signatures"), list)
        or not envelope["signatures"]
        or not all(
            isinstance(item, dict) and _decoded_base64(item.get("sig")) is not None
            for item in envelope["signatures"]
        )
    ):
        return False
    return True


def _release_provenance_signature_ok(
    release: dict[str, Any],
    manifest: dict[str, Any],
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Verify the package/control statement against its signed DSSE bundle."""
    controls = release.get("github_controls")
    controls_path = (
        _relative_candidate(controls.get("path"), root)
        if isinstance(controls, dict)
        else None
    )
    controls_bytes = _indexed_bytes(controls_path, context)
    policy = _signing_policy(manifest)
    identity = _github_release_certificate_identity(
        release.get("source_repository"),
        policy.get("github_controls_identity") if isinstance(policy, dict) else None,
    )
    if (
        not _indexed_dsse_statement_ok(
            release.get("provenance"), release.get("provenance_bundle"), root, context
        )
        or controls_bytes is None
        or controls_path is None
        or identity is None
    ):
        return False
    controls_digest = controls.get("digest") if isinstance(controls, dict) else None
    if controls_digest != "sha256:" + hashlib.sha256(controls_bytes).hexdigest():
        return False
    return _verify_sigstore_bundle(
        release["provenance_bundle"],
        controls_path,
        identity,
        SIGSTORE_GITHUB_OIDC_ISSUER,
        root,
        context,
        attestation=True,
    )


def _attestation_subject_digests(payload: dict[str, Any]) -> set[str]:
    """Return normalized SHA-256 subject digests from an in-toto statement."""
    subjects = payload.get("subject")
    if not isinstance(subjects, list):
        return set()
    digests: set[str] = set()
    for subject in subjects:
        if not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict):
            continue
        for algorithm, raw_digest in subject["digest"].items():
            if str(algorithm).lower() != "sha256":
                continue
            digest = str(raw_digest).lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                digests.add("sha256:" + digest)
            elif re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                digests.add(digest)
    return digests


def _attestation_subject_bindings(payload: dict[str, Any]) -> set[tuple[str, str]]:
    """Return (subject name, normalized digest) pairs from an attestation."""
    subjects = payload.get("subject")
    if not isinstance(subjects, list):
        return set()
    bindings: set[tuple[str, str]] = set()
    for subject in subjects:
        if not isinstance(subject, dict) or not _is_real_text(subject.get("name")):
            continue
        digests = subject.get("digest")
        if not isinstance(digests, dict):
            continue
        name = str(subject["name"])
        for algorithm, raw_digest in digests.items():
            if str(algorithm).lower() != "sha256":
                continue
            digest = str(raw_digest).lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                bindings.add((name, "sha256:" + digest))
            elif re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                bindings.add((name, digest))
    return bindings


def _provenance_binds_digests(payload: dict[str, Any] | None, expected: set[str]) -> bool:
    if payload is None or not expected:
        return False
    return expected <= _attestation_subject_digests(payload)


def _provenance_binds_subjects(payload: dict[str, Any] | None, expected: set[tuple[str, str]]) -> bool:
    if payload is None or not expected:
        return False
    return expected <= _attestation_subject_bindings(payload)


def _provenance_binds_source(
    payload: dict[str, Any] | None,
    repository: Any,
    source_revision: Any,
) -> bool:
    """Require SLSA resolved dependencies to bind the exact GitHub commit."""
    if (
        payload is None
        or not isinstance(repository, str)
        or GITHUB_REPOSITORY_RE.fullmatch(repository) is None
        or not isinstance(source_revision, str)
        or GITHUB_SOURCE_REVISION_RE.fullmatch(source_revision) is None
    ):
        return False
    predicate = payload.get("predicate")
    build_definition = (
        predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    )
    dependencies = (
        build_definition.get("resolvedDependencies")
        if isinstance(build_definition, dict)
        else None
    )
    if not isinstance(dependencies, list):
        return False
    repository_path = repository.casefold()
    expected_prefixes = (
        f"https://github.com/{repository_path}",
        f"https://github.com/{repository_path}.git",
        f"git+https://github.com/{repository_path}",
        f"git+https://github.com/{repository_path}.git",
    )
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("uri"), str):
            continue
        uri = dependency["uri"].casefold()
        uri_matches = any(
            uri == prefix or uri.startswith(prefix + "@")
            for prefix in expected_prefixes
        )
        digest = dependency.get("digest")
        if (
            uri_matches
            and isinstance(digest, dict)
            and digest.get("gitCommit") == source_revision
        ):
            return True
    return False


PROVENANCE_GROUPS = (("subject",), ("predicateType", "buildType", "payloadType", "materials"))
SBOM_GROUPS = (("spdxVersion", "bomFormat"), ("packages", "components"))


def _digest_matches(value: Any, digest: str, root: Path, context: EvidenceContext | None) -> bool:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return False
    measured = _indexed_measure(_relative_candidate(value, root), context)
    return measured is not None and measured[0] > 0 and f"sha256:{measured[1]}" == digest


def _oci_descriptor_ok(value: Any, *, config: bool) -> bool:
    if not isinstance(value, dict):
        return False
    media_type = value.get("mediaType")
    return bool(
        isinstance(media_type, str)
        and (
            media_type == OCI_IMAGE_CONFIG_MEDIA_TYPE
            if config
            else re.fullmatch(
                r"application/vnd\.oci\.image\.layer\.(?:nondistributable\.)?v1\.tar(?:\+(?:gzip|zstd))?",
                media_type,
            )
        )
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("digest", "")))
        and type(value.get("size")) is int
        and value["size"] > 0
    )


def _oci_image_manifest_ok(
    value: Any,
    image: str,
    digest: str,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Match a pinned image to the exact raw OCI image-manifest bytes."""
    if (
        not _oci_release_image_ref_ok(image)
        or digest != "sha256:" + image.rsplit("@sha256:", 1)[1]
    ):
        return False
    candidate = _relative_candidate(value, root)
    content = _indexed_bytes(candidate, context)
    if content is None or "sha256:" + hashlib.sha256(content).hexdigest() != digest:
        return False
    try:
        payload = load_json_document(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    layers = payload.get("layers")
    return bool(
        type(payload.get("schemaVersion")) is int
        and payload["schemaVersion"] == 2
        and payload.get("mediaType") == OCI_IMAGE_MANIFEST_MEDIA_TYPE
        and "artifactType" not in payload
        and "subject" not in payload
        and _oci_descriptor_ok(payload.get("config"), config=True)
        and isinstance(layers, list)
        and bool(layers)
        and all(_oci_descriptor_ok(layer, config=False) for layer in layers)
    )


def _image_provenance_ok(
    value: dict[str, Any],
    image: str,
    digest: str,
    signer: tuple[str, str],
    artifact_path: Path,
    root: Path,
    context: EvidenceContext | None,
) -> bool:
    """Require a separately signed image attestation for this exact image."""
    statement = value.get("provenance")
    bundle = value.get("provenance_bundle")
    payload = _provenance_payload(statement, root, context)
    return bool(
        _provenance_binds_subjects(payload, {(image.split("@", 1)[0], digest)})
        and _indexed_dsse_statement_ok(statement, bundle, root, context)
        and _verify_sigstore_bundle(
            bundle, artifact_path, signer[0], signer[1], root, context,
            attestation=True,
        )
    )


def _signed_artifact_ok(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
    *,
    freshness_policy: str = "release",
    signing_role: str = "release-artifact",
    expected_release: str | None = None,
) -> bool:
    """Verify one release or rollback artifact and its detached proof."""
    if not isinstance(value, dict):
        return False
    digest = str(value.get("digest", ""))
    image = value.get("image") if "image" in value else None
    if image is not None and not isinstance(image, str):
        return False
    if "image" in value and (
        not isinstance(image, str)
        or signing_role != "release-artifact"
        or not _oci_image_manifest_ok(value.get("path"), image, digest, root, context)
        or not _sbom_binds_named_sha256(
            value.get("sbom"), str(value.get("name", "")), digest, root, context
        )
    ):
        return False
    signer = _approved_signer(
        manifest,
        signing_role,
        value.get("name"),
        value.get("digest"),
        image=image,
        release_version=expected_release,
    )
    artifact_path = _relative_candidate(value.get("path"), root)
    referenced_paths = [
        _path_identity(value.get("path")),
        _path_identity(value.get("sbom")),
        _path_identity(value.get("signature")),
    ]
    if image is not None:
        referenced_paths.extend(
            (_path_identity(value.get("provenance")), _path_identity(value.get("provenance_bundle")))
        )
    if not (
        all(path is not None for path in referenced_paths)
        and len(set(referenced_paths)) == len(referenced_paths)
        and _is_real_text(value.get("name"))
        and _digest_matches(value.get("path"), digest, root, context)
        and _sbom_binds_name(value.get("sbom"), str(value.get("name", "")), root, context)
        and signer is not None
        and artifact_path is not None
        and (
            image is None
            or _image_provenance_ok(
                value, image, digest, signer, artifact_path, root, context
            )
        )
        and _sigstore_bundle_binds_digest(
            value.get("signature"), digest.removeprefix("sha256:"), root, context
        )
        and value.get("signature_verified") is True
        and _evidence_record_exists(
            value.get("signature_verification"),
            root,
            context,
            manifest,
            freshness_policy=freshness_policy,
        )
    ):
        return False
    signature_payload = _json_evidence_payload(value.get("signature_verification"), root, context)
    return bool(
        isinstance(signature_payload, dict)
        and signature_payload.get("artifact_digest") == digest
        and _is_real_text(signature_payload.get("verifier"))
        and signer is not None
        and artifact_path is not None
        and _verify_sigstore_bundle(
            value.get("signature"), artifact_path, signer[0], signer[1], root, context
        )
    )


def _execution_environment_ok(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
) -> bool:
    if not isinstance(value, dict):
        return False
    image = str(value.get("image", ""))
    digest = str(value.get("digest", ""))
    if not OCI_IMAGE_DIGEST_RE.fullmatch(image) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return False
    if digest != "sha256:" + image.rsplit("@sha256:", 1)[1]:
        return False
    signer = _approved_signer(
        manifest,
        "execution-environment",
        value.get("name"),
        value.get("digest"),
        image=image,
    )
    release = manifest.get("release")
    provenance_payload = _provenance_payload(value.get("provenance"), root, context)
    if (
        not _is_real_text(value.get("name"))
        or value.get("provenance_verified") is not True
        or provenance_payload is None
        or not _provenance_binds_digests(provenance_payload, {digest})
        or not _provenance_binds_subjects(provenance_payload, {(image.split("@", 1)[0], digest)})
        or not _provenance_binds_source(
            provenance_payload,
            release.get("source_repository") if isinstance(release, dict) else None,
            release.get("source_revision") if isinstance(release, dict) else None,
        )
        or not _sbom_binds_name(value.get("sbom"), str(value.get("name", "")), root, context)
        or signer is None
        or value.get("signature_verified") is not True
    ):
        return False
    verification = value.get("signature_verification")
    if not (
        _evidence_exists(verification, root, context)
        and _evidence_metadata_matches(
            verification, manifest, freshness_policy="release"
        )
    ):
        return False
    verification_payload = _json_evidence_payload(verification, root, context)
    verification_path = _relative_candidate(
        verification.get("evidence") if isinstance(verification, dict) else None,
        root,
    )
    verification_bytes = _indexed_bytes(verification_path, context)
    provenance_bytes = _indexed_bytes(_relative_candidate(value.get("provenance"), root), context)
    sbom_measure = _indexed_measure(_relative_candidate(value.get("sbom"), root), context)
    return bool(
        isinstance(verification_payload, dict)
        and verification_payload.get("schema_version") == 2
        and verification_payload.get("artifact_digest") == digest
        and verification_payload.get("image") == image
        and verification_payload.get("registry_digest") == digest
        and verification_payload.get("immutable_reference") == image
        and verification_payload.get("verifier") == "cosign"
        and verification_payload.get("source_revision") == (
            release.get("source_revision") if isinstance(release, dict) else None
        )
        and provenance_bytes is not None
        and verification_payload.get("provenance_sha256") == (
            "sha256:" + hashlib.sha256(provenance_bytes).hexdigest()
            if provenance_bytes is not None else None
        )
        and sbom_measure is not None
        and verification_payload.get("sbom_sha256") == (
            "sha256:" + sbom_measure[1] if sbom_measure is not None else None
        )
        and isinstance(verification, dict)
        and verification.get("artifact_digest") == digest
        and verification.get("image") == image
        and verification.get("verifier") == "cosign"
        and verification_bytes is not None
        and _sigstore_bundle_binds_content(
            value.get("signature"), verification_bytes, root, context
        )
        and signer is not None
        and _verify_sigstore_bundle(
            value.get("signature"), verification_bytes, signer[0], signer[1], root, context
        )
    )


def _expected_evidence_index_sha256(manifest: dict[str, Any]) -> str | None:
    value = manifest.get("evidence_index_digest")
    if not isinstance(value, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", value
    ):
        return None
    return value.split(":", 1)[1]


def _evidence_context(manifest: dict[str, Any], root: Path, catalog: Catalog) -> EvidenceContext | None:
    index_path = _relative_candidate(manifest.get("evidence_index"), root)
    expected_sha256 = _expected_evidence_index_sha256(manifest)
    if index_path is None or expected_sha256 is None:
        return None
    try:
        report = verify_evidence_index(
            index_path,
            expected_sha256=expected_sha256,
            include_entries=True,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    if report.get("status") != "pass":
        return None
    indexed_files = report.get("_entries")
    if not isinstance(indexed_files, dict):
        return None
    try:
        evidence_root = index_path.parent.resolve()
    except (OSError, RuntimeError):
        return None
    return evidence_root, indexed_files, catalog


def _evidence_index_errors(manifest: dict[str, Any], root: Path) -> list[str]:
    index_path = _relative_candidate(manifest.get("evidence_index"), root)
    if index_path is None:
        return ["evidence_index must identify a readable relative SHA-256 index file"]
    expected_sha256 = _expected_evidence_index_sha256(manifest)
    if expected_sha256 is None:
        return [
            "evidence_index_digest must be a lowercase sha256: digest of the exact index bytes"
        ]
    try:
        report = verify_evidence_index(index_path, expected_sha256=expected_sha256)
    except (OSError, RuntimeError, ValueError) as exc:
        return [f"evidence_index verification failed: {exc}"]
    if report.get("status") == "pass":
        return []
    details = "; ".join(str(error) for error in report.get("errors", []))
    return [f"evidence_index verification failed: {details or 'unknown verification error'}"]


def _all_pass_with_evidence(
    values: Any,
    root: Path,
    context: EvidenceContext | None,
    required_names: set[str] | None = None,
    manifest: dict[str, Any] | None = None,
    freshness_policy: str | None = None,
) -> bool:
    if not isinstance(values, list) or not values:
        return False
    if manifest is None:
        records_pass = all(
            isinstance(item, dict)
            and _is_real_text(item.get("name"))
            and _evidence_exists(item, root, context)
            for item in values
        )
    elif freshness_policy is None:
        records_pass = False
    else:
        records_pass = all(
            isinstance(item, dict)
            and _is_real_text(item.get("name"))
            and _evidence_record_exists(
                item,
                root,
                context,
                manifest,
                freshness_policy=f"{freshness_policy}.{item.get('name')}",
            )
            for item in values
        )
    if not records_pass:
        return False
    names = [str(item["name"]).lower() for item in values]
    evidence_paths = [
        _path_identity(item.get("evidence"))
        for item in values
        if isinstance(item, dict)
    ]
    return (
        (not required_names or {name.lower() for name in required_names} <= set(names))
        and len(set(names)) == len(values)
        and len(evidence_paths) == len(values)
        and all(path is not None for path in evidence_paths)
        and len(set(evidence_paths)) == len(values)
    )


def _section_pass(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") == "pass"


def _section_evidence_ok(
    section: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
    *,
    section_name: str,
) -> bool:
    return _section_pass(section) and _evidence_record_exists(
        section,
        root,
        context,
        manifest,
        freshness_policy=section_name,
    )


def _claim_evidence_ok(
    section_name: str,
    section: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
) -> bool:
    required_fields = CLAIM_EVIDENCE_FIELDS.get(section_name, ())
    if not isinstance(section, dict):
        return False
    records = [section.get(field) for field in required_fields]
    if not all(
        _evidence_record_exists(
            record,
            root,
            context,
            manifest,
            freshness_policy=f"{section_name}.{field}",
        )
        for field, record in zip(required_fields, records)
    ):
        return False
    evidence_paths = [
        _path_identity(record.get("evidence"))
        for record in records
        if isinstance(record, dict)
    ]
    names = [str(record["name"]).lower() for record in records if isinstance(record, dict)]
    return (
        len(evidence_paths) == len(records)
        and all(path is not None for path in evidence_paths)
        and len(set(evidence_paths)) == len(records)
        and len(set(names)) == len(records)
    )


def _matching_passing_value(
    manifest: dict[str, Any],
    left_section_name: str,
    left_field_name: str,
    right_section_name: str,
    right_field_name: str,
    validator: Callable[[Any], bool],
) -> bool:
    left_section = manifest.get(left_section_name)
    right_section = manifest.get(right_section_name)
    if not (
        isinstance(left_section, dict)
        and isinstance(right_section, dict)
        and _section_pass(left_section)
        and _section_pass(right_section)
    ):
        return True
    left_value = left_section.get(left_field_name)
    right_value = right_section.get(right_field_name)
    return not (validator(left_value) and validator(right_value)) or left_value == right_value


def _change_control_binding_ok(manifest: dict[str, Any]) -> bool:
    return _matching_passing_value(
        manifest,
        "control",
        "change_ticket",
        "governance",
        "change_ticket",
        _is_real_text,
    )


def _service_objectives_binding_ok(manifest: dict[str, Any]) -> bool:
    return all(
        _matching_passing_value(
            manifest,
            "data_protection",
            field,
            "support",
            field,
            lambda value: type(value) is int and value > 0,
        )
        for field in ("rpo_minutes", "rto_minutes")
    )


def _on_call_binding_ok(manifest: dict[str, Any]) -> bool:
    return _matching_passing_value(
        manifest,
        "observability",
        "on_call",
        "support",
        "on_call",
        _is_real_text,
    )


def _control_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("control")
    if not isinstance(section, dict):
        return False
    return bool(
        context is not None
        and _section_evidence_ok(
            section,
            root,
            context,
            manifest,
            section_name="control",
        )
        and section.get("catalog_validated") is True
        and section.get("ci_green") is True
        and _is_real_text(section.get("change_ticket"))
        and _change_control_binding_ok(manifest)
    )


def _release_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("release")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="release",
    ):
        return False
    provenance_payload = _provenance_payload(
        section.get("provenance"),
        root,
        context,
    )
    if (
        not _is_real_text(section.get("version"))
        or section.get("provenance_verified") is not True
        or provenance_payload is None
        or not _provenance_binds_source(
            provenance_payload,
            section.get("source_repository"),
            section.get("source_revision"),
        )
        or not _release_provenance_signature_ok(section, manifest, root, context)
        or not _github_controls_ok(section, manifest, root, context)
    ):
        return False
    artifacts = section.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or not all(
        _signed_artifact_ok(item, root, context, manifest) for item in artifacts
    ):
        return False
    service = manifest.get("service")
    selected_runtime = (
        service.get("underlying_runtime")
        if isinstance(service, dict) and service.get("runtime") == "ansible"
        else service.get("runtime") if isinstance(service, dict) else None
    )
    image_artifacts = [item for item in artifacts if isinstance(item, dict) and "image" in item]
    image_refs = [item["image"] for item in image_artifacts]
    if (
        len(image_refs) != len(set(image_refs))
        or selected_runtime in OCI_PROOF_RUNTIME_IDS and not image_artifacts
    ):
        return False
    release_proof_path_entries = _release_proof_path_entries(section)
    if len(release_proof_path_entries) != len(set(release_proof_path_entries)):
        return False
    release_proof_name_entries = _release_proof_name_entries(section)
    if len(release_proof_name_entries) != len(set(release_proof_name_entries)):
        return False
    release_artifact_proof_paths: set[str] = set()
    for artifact in artifacts:
        artifact_paths = _artifact_proof_paths(artifact)
        if (
            len(_artifact_core_proof_paths(artifact)) != 3
            or release_artifact_proof_paths.intersection(artifact_paths)
        ):
            return False
        release_artifact_proof_paths.update(artifact_paths)
    expected_release_digests = {
        str(item.get("digest", ""))
        for item in artifacts
        if isinstance(item, dict) and "image" not in item
    }
    expected_release_subjects = {
        (str(item.get("name", "")), str(item.get("digest", "")))
        for item in artifacts
        if isinstance(item, dict) and "image" not in item
    }
    github_controls = section.get("github_controls")
    if not isinstance(github_controls, dict):
        return False
    github_controls_path = _path_identity(github_controls.get("path"))
    github_controls_digest = str(github_controls.get("digest", ""))
    if github_controls_path is None:
        return False
    expected_release_digests.add(github_controls_digest)
    expected_release_subjects.add(
        (Path(github_controls_path).name, github_controls_digest)
    )
    all_release_proof_paths = set(release_artifact_proof_paths)
    github_controls_paths = _github_controls_proof_paths(section.get("github_controls"))
    if (
        len(github_controls_paths) != 3
        or all_release_proof_paths.intersection(github_controls_paths)
    ):
        return False
    all_release_proof_paths.update(github_controls_paths)
    if isinstance(service, dict) and service.get("runtime") == "ansible":
        provider_bundle = section.get("provider_bundle")
        if isinstance(provider_bundle, dict):
            provider_paths = _artifact_proof_paths(provider_bundle)
            if (
                len(_artifact_core_proof_paths(provider_bundle)) != 3
                or all_release_proof_paths.intersection(provider_paths)
            ):
                return False
            all_release_proof_paths.update(provider_paths)
            expected_release_digests.add(str(provider_bundle.get("digest", "")))
            expected_release_subjects.add(
                (str(provider_bundle.get("name", "")), str(provider_bundle.get("digest", "")))
            )
    if not _provenance_binds_digests(provenance_payload, expected_release_digests):
        return False
    if not _provenance_binds_subjects(provenance_payload, expected_release_subjects):
        return False
    if not isinstance(service, dict) or service.get("runtime") != "ansible":
        return True
    provider_bundle = section.get("provider_bundle")
    execution_environment = section.get("execution_environment")
    execution_environment_proof_paths = _execution_environment_proof_paths(execution_environment)
    if (
        len(_execution_environment_core_proof_paths(execution_environment)) != 3
        or all_release_proof_paths.intersection(execution_environment_proof_paths)
    ):
        return False
    provider_verification = _json_evidence_payload(
        provider_bundle.get("verification") if isinstance(provider_bundle, dict) else None,
        root,
        context,
    )
    return bool(
        isinstance(provider_bundle, dict)
        and _is_real_text(provider_bundle.get("name"))
        and _signed_artifact_ok(
            provider_bundle, root, context, manifest, signing_role="provider-bundle"
        )
        and _digest_matches(provider_bundle.get("path"), str(provider_bundle.get("digest", "")), root, context)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(provider_bundle.get("remote_digest", "")))
        and _evidence_record_exists(
            provider_bundle.get("verification"),
            root,
            context,
            manifest,
            freshness_policy="release.provider_bundle.verification",
        )
        and isinstance(provider_verification, dict)
        and provider_verification.get("artifact_digest") == provider_bundle.get("digest")
        and provider_verification.get("remote_digest") == provider_bundle.get("remote_digest")
        and _is_real_text(provider_verification.get("verifier"))
        and _execution_environment_ok(execution_environment, root, context, manifest)
    )


def _product_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("product_certification")
    if (
        not isinstance(section, dict)
        or not _section_evidence_ok(
            section,
            root,
            context,
            manifest,
            section_name="product_certification",
        )
        or context is None
    ):
        return False
    service = manifest.get("service")
    if not isinstance(service, dict):
        return False
    solution = context[2].solutions.get(str(service.get("solution_id")))
    if solution is None:
        return False
    required_dependencies = {str(item).lower() for item in solution.get("dependencies", [])}
    required_formats = {str(item).lower() for item in solution.get("format_profiles", [])}
    required_components = {str(item).lower() for item in solution.get("architecture_components", [])}
    dependency_coverage = section.get("dependency_coverage")
    format_coverage = section.get("format_coverage")
    component_coverage = section.get("component_coverage")
    return bool(
        isinstance(dependency_coverage, list)
        and {str(item).lower() for item in dependency_coverage if _is_real_text(item)} >= required_dependencies
        and isinstance(format_coverage, list)
        and {str(item).lower() for item in format_coverage if _is_real_text(item)} >= required_formats
        and isinstance(component_coverage, list)
        and {str(item).lower() for item in component_coverage if _is_real_text(item)} >= required_components
        and isinstance(section.get("test_matrix"), list)
        and len(section["test_matrix"]) >= 5
        and _all_pass_with_evidence(
            section.get("test_matrix"),
            root,
            context,
            {"dependencies", "smoke", "migration", "formats", "api"},
            manifest,
            freshness_policy="product_certification.test_matrix",
        )
    )


def _resilience_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("resilience")
    if not isinstance(section, dict):
        return False
    return bool(
        _section_evidence_ok(
            section,
            root,
            context,
            manifest,
            section_name="resilience",
        )
        and section.get("quorum_verified") is True
        and section.get("fencing_verified") is True
        and isinstance(section.get("failure_tests"), list)
        and len(section["failure_tests"]) >= 4
        and _all_pass_with_evidence(
            section.get("failure_tests"),
            root,
            context,
            {"node", "service", "dependency", "storage"},
            manifest,
            freshness_policy="resilience.failure_tests",
        )
    )


def _data_protection_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("data_protection")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="data_protection",
    ):
        return False
    backup = section.get("backup")
    restore = section.get("restore_test")
    fixity = section.get("fixity_test")
    return bool(
        isinstance(backup, dict)
        and type(backup.get("immutable_copies")) is int
        and backup.get("immutable_copies", 0) >= 2
        and _evidence_record_exists(
            backup,
            root,
            context,
            manifest,
            freshness_policy="data_protection.backup",
        )
        and _evidence_record_exists(
            restore,
            root,
            context,
            manifest,
            freshness_policy="data_protection.restore_test",
        )
        and _evidence_record_exists(
            fixity,
            root,
            context,
            manifest,
            freshness_policy="data_protection.fixity_test",
        )
        and type(section.get("rpo_minutes")) is int
        and section.get("rpo_minutes", 0) > 0
        and type(section.get("rto_minutes")) is int
        and section.get("rto_minutes", 0) > 0
        and _service_objectives_binding_ok(manifest)
    )


def _security_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("security")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="security",
    ):
        return False
    return bool(
        _claim_evidence_ok("security", section, root, context, manifest)
        and section.get("sbom_verified") is True
        and section.get("tls_verified") is True
        and _is_real_text(section.get("secrets_provider"))
        and _evidence_record_exists(
            section.get("vulnerability_scan"),
            root,
            context,
            manifest,
            freshness_policy="security.vulnerability_scan",
        )
        and _evidence_record_exists(
            section.get("penetration_test"),
            root,
            context,
            manifest,
            freshness_policy="security.penetration_test",
        )
    )


def _observability_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("observability")
    if not _deployment_target_complete(manifest) or not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="observability",
    ):
        return False
    return bool(
        _claim_evidence_ok("observability", section, root, context, manifest)
        and all(_is_real_text(section.get(key)) for key in ("metrics", "alerts", "dashboards", "on_call"))
        and _on_call_binding_ok(manifest)
        and _evidence_record_exists(
            section.get("alert_delivery_test"),
            root,
            context,
            manifest,
            freshness_policy="observability.alert_delivery_test",
        )
    )


def _recovery_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("recovery")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="recovery",
    ):
        return False
    release = manifest.get("release")
    current_release = release.get("version") if isinstance(release, dict) else None
    rollback_release = section.get("rollback_release")
    rollback_artifact = section.get("rollback_artifact")
    rollback_digest = str(section.get("rollback_artifact_digest", ""))
    return bool(
        _is_real_text(rollback_release)
        and rollback_release != current_release
        and re.fullmatch(r"sha256:[0-9a-f]{64}", rollback_digest)
        and isinstance(rollback_artifact, dict)
        and rollback_artifact.get("digest") == rollback_digest
        and _signed_artifact_ok(
            rollback_artifact,
            root,
            context,
            manifest,
            freshness_policy="recovery.rollback_artifact",
            signing_role="rollback-artifact",
            expected_release=rollback_release if isinstance(rollback_release, str) else None,
        )
        and _evidence_record_exists(
            section.get("rollback_test"),
            root,
            context,
            manifest,
            freshness_policy="recovery.rollback_test",
        )
        and _evidence_record_exists(
            section.get("repair_test"),
            root,
            context,
            manifest,
            freshness_policy="recovery.repair_test",
        )
        and not _artifact_proof_paths(rollback_artifact).intersection(
            _release_proof_paths(release)
        )
        and str(rollback_artifact.get("name", "")).casefold()
        not in _release_proof_names(release)
    )


def _governance_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("governance")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="governance",
    ):
        return False
    return bool(
        _is_real_text(section.get("change_ticket"))
        and _is_real_text(section.get("approved_by"))
        and _is_real_timestamp(section.get("approved_at"))
        and _is_real_timestamp(section.get("valid_until"))
        and not _approval_window_errors(section)
        and section.get("evidence_immutable") is True
        and section.get("evidence_access_logged") is True
        and type(section.get("evidence_retention_days")) is int
        and section.get("evidence_retention_days", 0) > 0
        and _change_control_binding_ok(manifest)
        and _evidence_record_exists(
            section.get("retention_control"),
            root,
            context,
            manifest,
            freshness_policy="governance.retention_control",
        )
        and _evidence_record_exists(
            section.get("risk_review"),
            root,
            context,
            manifest,
            freshness_policy="governance.risk_review",
        )
    )


def _support_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("support")
    if not isinstance(section, dict) or not _section_evidence_ok(
        section,
        root,
        context,
        manifest,
        section_name="support",
    ):
        return False
    return bool(
        _claim_evidence_ok("support", section, root, context, manifest)
        and _is_real_text(section.get("service_owner"))
        and _is_real_text(section.get("on_call"))
        and _is_real_text(section.get("sla"))
        and type(section.get("rpo_minutes")) is int
        and section.get("rpo_minutes", 0) > 0
        and type(section.get("rto_minutes")) is int
        and section.get("rto_minutes", 0) > 0
        and _service_objectives_binding_ok(manifest)
        and _on_call_binding_ok(manifest)
        and isinstance(section.get("runbooks"), list)
        and bool(section.get("runbooks"))
        and all(_relative_file(item, root, context) for item in section.get("runbooks", []))
    )


CRITERIA: tuple[tuple[str, str, int, Callable[[dict[str, Any], Path, EvidenceContext | None], bool]], ...] = (
    ("control", "Catalog, CI, and change-control baseline", 10, _control_ok),
    ("release", "Pinned release, provenance, SBOM, and signatures", 10, _release_ok),
    ("product", "Product-specific release certification", 10, _product_ok),
    ("resilience", "Quorum, fencing, and failure-domain tests", 10, _resilience_ok),
    ("data_protection", "Immutable backup, restore, and fixity proof", 10, _data_protection_ok),
    ("security", "Security scans, TLS, and secret-management proof", 10, _security_ok),
    ("observability", "Metrics, alerts, dashboards, and on-call", 10, _observability_ok),
    ("recovery", "Rollback and repair validation", 10, _recovery_ok),
    ("governance", "Approval, risk review, and audit evidence", 10, _governance_ok),
    ("support", "SLA, ownership, RPO/RTO, and runbooks", 10, _support_ok),
)


def validate_manifest(manifest: Any, catalog: Catalog) -> list[str]:
    if not isinstance(manifest, dict):
        return ["readiness manifest must contain a JSON object"]
    shape_errors = _json_shape_errors(
        manifest,
        "readiness manifest",
        max_nodes=MAX_MANIFEST_JSON_NODES,
    )
    if shape_errors:
        return shape_errors
    errors: list[str] = []
    errors.extend(f"missing top-level field '{field}'" for field in sorted(REQUIRED_TOP_LEVEL - set(manifest)))
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    errors.extend(_deployment_target_errors(manifest))
    service = manifest.get("service", {})
    solution: dict[str, Any] | None = None
    if not isinstance(service, dict):
        errors.append("service must be an object")
    else:
        solution_id = service.get("solution_id")
        try:
            solution = catalog.solution(str(solution_id))
        except ValueError:
            errors.append(f"service.solution_id is not present in the catalog: {solution_id!r}")
        runtime = service.get("runtime")
        selected_runtime = runtime
        try:
            catalog.runtime(str(runtime))
        except ValueError:
            errors.append(f"service.runtime is not present in the catalog: {runtime!r}")
        if runtime == "ansible":
            underlying = service.get("underlying_runtime")
            selected_runtime = underlying
            try:
                catalog.runtime(str(underlying))
            except ValueError:
                errors.append("service.underlying_runtime must identify the runtime coordinated by Ansible")
            if underlying == "ansible":
                errors.append("service.underlying_runtime cannot be ansible")
        if (
            solution is not None
            and isinstance(selected_runtime, str)
            and selected_runtime in catalog.runtimes
        ):
            support_level = solution["mode_support"].get(selected_runtime)
            if support_level == "not-recommended":
                errors.append(f"service runtime '{selected_runtime}' is not-recommended for {solution_id}")
            if support_level == "conditional" and service.get("conditional_design_approved") is not True:
                errors.append("service.conditional_design_approved must be true for a conditional product/runtime pairing")
        try:
            catalog.operating_system(str(service.get("os_id")))
        except ValueError:
            errors.append("service.os_id must identify an operating system in the catalog")
        if (
            not isinstance(service.get("environment"), str)
            or service.get("environment") not in ENVIRONMENT_VALUES
        ):
            errors.append("service.environment must identify a supported target environment")
    release = manifest.get("release", {})
    if isinstance(release, dict) and not _is_real_text(release.get("version")):
        errors.append("release.version must be a non-placeholder pinned release")
    if isinstance(release, dict) and release.get("status") == "pass":
        if not _is_real_text(release.get("provenance_bundle")) or not str(
            release.get("provenance_bundle", "")
        ).endswith(".sigstore.json"):
            errors.append(
                "release.provenance_bundle must identify the indexed Sigstore DSSE attestation"
            )
        source_repository = release.get("source_repository")
        source_parts = (
            source_repository.split("/", maxsplit=1)
            if isinstance(source_repository, str)
            else []
        )
        if (
            not isinstance(source_repository, str)
            or GITHUB_REPOSITORY_RE.fullmatch(source_repository) is None
            or any(part in {".", ".."} for part in source_parts)
        ):
            errors.append(
                "release.source_repository must identify the GitHub owner/repository"
            )
        source_repository_id = release.get("source_repository_id")
        if (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or source_repository_id <= 0
        ):
            errors.append("release.source_repository_id must be a positive GitHub repository ID")
        if GITHUB_SOURCE_REVISION_RE.fullmatch(
            str(release.get("source_revision", ""))
        ) is None:
            errors.append(
                "release.source_revision must be a lowercase 40-character commit SHA"
            )
        github_controls = release.get("github_controls")
        if not isinstance(github_controls, dict):
            errors.append(
                "release.github_controls must be a signed hosted-control audit reference"
            )
        else:
            if set(github_controls) != GITHUB_AUDIT_REFERENCE_FIELDS:
                errors.append(
                    "release.github_controls must contain exactly the signed-audit fields"
                )
            report_path = github_controls.get("path")
            if (
                not _is_real_text(report_path)
                or Path(str(report_path)).suffix.lower() != ".json"
            ):
                errors.append(
                    "release.github_controls.path must identify the indexed JSON audit"
                )
            if re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(github_controls.get("digest", ""))
            ) is None:
                errors.append(
                    "release.github_controls.digest must be a SHA-256 digest"
                )
            if not _is_real_text(github_controls.get("signature")):
                errors.append(
                    "release.github_controls.signature must identify the Sigstore bundle"
                )
            if github_controls.get("signature_verified") is not True:
                errors.append("release.github_controls.signature_verified must be true")
            signature_verification = github_controls.get("signature_verification")
            if (
                not isinstance(signature_verification, dict)
                or signature_verification.get("status") != "pass"
            ):
                errors.append(
                    "release.github_controls.signature_verification must be passing evidence"
                )
    control = manifest.get("control")
    if isinstance(control, dict) and control.get("status") == "pass" and not _is_real_text(control.get("change_ticket")):
        errors.append("control.change_ticket must identify the approved change-control record")
    if isinstance(service, dict) and service.get("runtime") == "ansible" and isinstance(release, dict) and release.get("status") == "pass":
        provider_bundle = release.get("provider_bundle")
        if not isinstance(provider_bundle, dict):
            errors.append("release.provider_bundle is required for Ansible certification")
        else:
            if not _is_real_text(provider_bundle.get("name")):
                errors.append("release.provider_bundle.name must identify the reviewed provider bundle")
            if not _is_real_text(provider_bundle.get("path")):
                errors.append("release.provider_bundle.path must identify the provider bundle artifact")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(provider_bundle.get("digest", ""))):
                errors.append("release.provider_bundle.digest must be a SHA-256 digest")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(provider_bundle.get("remote_digest", ""))):
                errors.append("release.provider_bundle.remote_digest must be a SHA-256 digest")
            if not _is_real_text(provider_bundle.get("sbom")):
                errors.append("release.provider_bundle.sbom must identify the provider-bundle SBOM")
            if not _is_real_text(provider_bundle.get("signature")):
                errors.append("release.provider_bundle.signature must identify the provider-bundle signature")
            if provider_bundle.get("signature_verified") is not True:
                errors.append("release.provider_bundle.signature_verified must be true")
            signature_verification = provider_bundle.get("signature_verification")
            if not isinstance(signature_verification, dict) or signature_verification.get("status") != "pass":
                errors.append("release.provider_bundle.signature_verification must be a passing evidence record")
            verification = provider_bundle.get("verification")
            if not isinstance(verification, dict) or verification.get("status") != "pass":
                errors.append("release.provider_bundle.verification must be a passing evidence record")
        execution_environment = release.get("execution_environment")
        if not isinstance(execution_environment, dict):
            errors.append("release.execution_environment is required for Ansible certification")
        else:
            if not _is_real_text(execution_environment.get("name")):
                errors.append("release.execution_environment.name must identify the reviewed controller image")
            image = str(execution_environment.get("image", ""))
            digest = str(execution_environment.get("digest", ""))
            if not OCI_IMAGE_DIGEST_RE.fullmatch(image):
                errors.append("release.execution_environment.image must be an immutable OCI digest reference")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                errors.append("release.execution_environment.digest must be a SHA-256 digest")
            elif OCI_IMAGE_DIGEST_RE.fullmatch(image) and digest != "sha256:" + image.rsplit("@sha256:", 1)[1]:
                errors.append("release.execution_environment.digest must match the image digest")
            if execution_environment.get("provenance_verified") is not True:
                errors.append("release.execution_environment.provenance_verified must be true")
            if not _is_real_text(execution_environment.get("provenance")):
                errors.append("release.execution_environment.provenance must identify the controller-image attestation")
            if not _is_real_text(execution_environment.get("sbom")):
                errors.append("release.execution_environment.sbom must identify the controller-image SBOM")
            if not _is_real_text(execution_environment.get("signature")):
                errors.append("release.execution_environment.signature must identify the controller-image signature")
            if execution_environment.get("signature_verified") is not True:
                errors.append("release.execution_environment.signature_verified must be true")
            verification = execution_environment.get("signature_verification")
            if not isinstance(verification, dict) or verification.get("status") != "pass":
                errors.append("release.execution_environment.signature_verification must be a passing evidence record")
    if isinstance(release, dict) and release.get("status") == "pass":
        proof_path_entries = _release_proof_path_entries(release)
        if len(proof_path_entries) != len(set(proof_path_entries)):
            errors.append(
                "release proof paths must be unique across release attestations"
            )
        proof_name_entries = _release_proof_name_entries(release)
        if len(proof_name_entries) != len(set(proof_name_entries)):
            errors.append(
                "release artifact names must be unique across release attestations"
            )
        artifacts = release.get("artifacts")
        if isinstance(artifacts, list):
            artifact_names = [
                str(item.get("name", "")).casefold()
                for item in artifacts
                if isinstance(item, dict)
            ]
            artifact_paths = [str(item.get("path", "")) for item in artifacts if isinstance(item, dict)]
            if len(artifact_names) != len(set(artifact_names)):
                errors.append("release.artifacts must not contain duplicate artifact names")
            if len(artifact_paths) != len(set(artifact_paths)):
                errors.append("release.artifacts must not contain duplicate artifact paths")
            image_refs: list[str] = []
            for index, item in enumerate(artifacts):
                if not isinstance(item, dict) or "image" not in item:
                    continue
                artifact_image = item.get("image")
                if not isinstance(artifact_image, str) or not _oci_release_image_ref_ok(artifact_image):
                    errors.append(
                        f"release.artifacts[{index}].image must be an exact repository@sha256 OCI reference"
                    )
                    continue
                image_refs.append(artifact_image)
                if item.get("digest") != "sha256:" + artifact_image.rsplit("@sha256:", 1)[1]:
                    errors.append(
                        f"release.artifacts[{index}].digest must match the image digest"
                    )
                for field in ("provenance", "provenance_bundle"):
                    if not _is_real_text(item.get(field)):
                        errors.append(
                            f"release.artifacts[{index}].{field} must identify indexed image provenance"
                        )
            if len(image_refs) != len(set(image_refs)):
                errors.append("release.artifacts image references must be unique")
            if (
                isinstance(service, dict)
                and (
                    service.get("underlying_runtime")
                    if service.get("runtime") == "ansible"
                    else service.get("runtime")
                ) in OCI_PROOF_RUNTIME_IDS
                and not image_refs
            ):
                errors.append("release.artifacts must include an OCI image for container runtimes")
            if isinstance(service, dict) and service.get("runtime") == "ansible":
                provider_bundle = release.get("provider_bundle")
                if isinstance(provider_bundle, dict) and str(provider_bundle.get("name", "")).casefold() in artifact_names:
                    errors.append("release.provider_bundle.name must be distinct from release.artifacts names")
    if _expected_evidence_index_sha256(manifest) is None:
        errors.append(
            "evidence_index_digest must be a lowercase sha256: digest of the exact index bytes"
        )
    for section_name in sorted(
        REQUIRED_TOP_LEVEL
        - {"schema_version", "service", "evidence_index", "evidence_index_digest"}
    ):
        section = manifest.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"{section_name} must be an object")
        elif (
            not isinstance(section.get("status"), str)
            or section.get("status") not in STATUS_VALUES
        ):
            errors.append(f"{section_name}.status must be pass, pending, or fail")
    governance = manifest.get("governance")
    if isinstance(governance, dict) and governance.get("status") == "pass":
        errors.extend(_approval_window_errors(governance))
    for section_name, required_fields in CLAIM_EVIDENCE_FIELDS.items():
        section = manifest.get(section_name)
        if isinstance(section, dict) and section.get("status") == "pass":
            for field in required_fields:
                record = section.get(field)
                if not isinstance(record, dict) or record.get("status") != "pass":
                    errors.append(f"{section_name}.{field} must be a passing evidence record")
    if not _change_control_binding_ok(manifest):
        errors.append("control.change_ticket must match governance.change_ticket when both sections pass")
    for field in ("rpo_minutes", "rto_minutes"):
        if not _matching_passing_value(
            manifest,
            "data_protection",
            field,
            "support",
            field,
            lambda value: type(value) is int and value > 0,
        ):
            errors.append(f"support.{field} must match data_protection.{field} when both sections pass")
    if not _on_call_binding_ok(manifest):
        errors.append("observability.on_call must match support.on_call when both sections pass")
    recovery = manifest.get("recovery")
    if isinstance(recovery, dict) and recovery.get("status") == "pass":
        rollback_artifact = recovery.get("rollback_artifact")
        if not isinstance(rollback_artifact, dict):
            errors.append("recovery.rollback_artifact is required for a passing recovery record")
        else:
            if not _is_real_text(rollback_artifact.get("name")):
                errors.append("recovery.rollback_artifact.name must identify the previous release artifact")
            if not _is_real_text(rollback_artifact.get("path")):
                errors.append("recovery.rollback_artifact.path must identify the previous release artifact")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(rollback_artifact.get("digest", ""))):
                errors.append("recovery.rollback_artifact.digest must be a SHA-256 digest")
            if not _is_real_text(rollback_artifact.get("sbom")):
                errors.append("recovery.rollback_artifact.sbom must identify the previous artifact SBOM")
            if not _is_real_text(rollback_artifact.get("signature")):
                errors.append("recovery.rollback_artifact.signature must identify the previous artifact signature")
            if rollback_artifact.get("signature_verified") is not True:
                errors.append("recovery.rollback_artifact.signature_verified must be true")
            verification = rollback_artifact.get("signature_verification")
            if not isinstance(verification, dict) or verification.get("status") != "pass":
                errors.append("recovery.rollback_artifact.signature_verification must be a passing evidence record")
            rollback_name = rollback_artifact.get("name")
            if (
                _is_real_text(rollback_name)
                and str(rollback_name).casefold() in _release_proof_names(release)
            ):
                errors.append(
                    "recovery.rollback_artifact.name must be distinct from release artifact names"
                )
            if _artifact_proof_paths(rollback_artifact).intersection(
                _release_proof_paths(release)
            ):
                errors.append(
                    "recovery.rollback_artifact proof paths must be distinct from release attestations"
                )
    if solution is not None:
        errors.extend(_catalog_coverage_errors(manifest.get("product_certification"), solution))
    for key, value in _walk_keys(manifest):
        if _is_secret_bearing_key(key):
            errors.append(f"secret-bearing field '{key}' is not allowed in a readiness manifest")
        if key.lower() in {
            "path",
            "sbom",
            "signature",
            "provenance",
            "provenance_bundle",
            "evidence",
            "evidence_index",
            "github_controls",
        } and isinstance(value, str):
            path_value = Path(value)
            if (
                path_value.is_absolute()
                or path_value.anchor
                or path_value.drive
                or WINDOWS_ABSOLUTE_RE.match(value)
                or "\\" in value
                or "\x00" in value
                or ".." in path_value.parts
            ):
                errors.append(f"path field '{key}' must stay inside the readiness evidence bundle")
        if isinstance(value, str) and "-----begin " in value.lower():
            errors.append(f"private-key material is not allowed in field '{key}'")
    errors.extend(_evidence_metadata_errors(manifest))
    return errors


def _walk_keys(value: Any) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.append((str(key), child))
            found.extend(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_keys(child))
    return found


def _catalog_coverage_errors(section: Any, solution: dict[str, Any]) -> list[str]:
    if not isinstance(section, dict) or section.get("status") != "pass":
        return []
    errors: list[str] = []
    for manifest_key, catalog_key in (("dependency_coverage", "dependencies"), ("format_coverage", "format_profiles"), ("component_coverage", "architecture_components")):
        required = {str(item).lower() for item in solution.get(catalog_key, [])}
        declared = section.get(manifest_key)
        if not isinstance(declared, list):
            errors.append(f"product_certification.{manifest_key} must be a list covering the selected catalog entry")
            continue
        present = {str(item).lower() for item in declared if _is_real_text(item)}
        missing = sorted(required - present)
        if missing:
            errors.append(f"product_certification.{manifest_key} is missing catalog coverage: {', '.join(missing)}")
    return errors


def _evidence_metadata_errors(
    manifest: dict[str, Any],
    *,
    now: datetime | None = None,
) -> list[str]:
    release = manifest.get("release")
    service = manifest.get("service")
    release_version = release.get("version") if isinstance(release, dict) else None
    execution_environment = release.get("execution_environment") if isinstance(release, dict) else None
    execution_environment_digest = execution_environment.get("digest") if isinstance(execution_environment, dict) else None
    solution_id = service.get("solution_id") if isinstance(service, dict) else None
    runtime = service.get("runtime") if isinstance(service, dict) else None
    underlying_runtime = service.get("underlying_runtime") if isinstance(service, dict) else None
    os_id = service.get("os_id") if isinstance(service, dict) else None
    environment = service.get("environment") if isinstance(service, dict) else None
    current = now or datetime.now(timezone.utc)
    errors: list[str] = []
    evidence_references: dict[str, list[str]] = {}

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("status") == "pass" and "evidence" in value:
                evidence = value.get("evidence")
                if isinstance(evidence, str):
                    # The path validator rejects traversal and absolute paths;
                    # normalize harmless spelling differences so `./proof.json`
                    # cannot evade the one-record/one-file rule.
                    normalized_evidence = _path_identity(evidence)
                    if normalized_evidence is not None:
                        evidence_references.setdefault(normalized_evidence, []).append(path or "<root>")
                if _operational_run_receipt_required(manifest, path):
                    receipt = value.get("run_receipt")
                    hook = value.get("run_hook")
                    if (
                        not isinstance(receipt, dict)
                        or set(receipt) != {"path", "signature", "signer"}
                        or not _is_real_text(receipt.get("signer"))
                    ):
                        errors.append(f"{path}.run_receipt must identify an indexed signed operational receipt")
                    else:
                        for field in ("path", "signature"):
                            normalized = _path_identity(receipt.get(field))
                            if normalized is None:
                                errors.append(f"{path}.run_receipt.{field} must be a relative indexed path")
                            else:
                                evidence_references.setdefault(normalized, []).append(
                                    f"{path}.run_receipt.{field}"
                                )
                    if (
                        not isinstance(hook, dict)
                        or set(hook) != {"executable_sha256", "argv_sha256"}
                        or any(
                            not isinstance(hook.get(field), str)
                            or re.fullmatch(r"[0-9a-f]{64}", hook[field]) is None
                            for field in ("executable_sha256", "argv_sha256")
                        )
                    ):
                        errors.append(f"{path}.run_hook must pin executable and argument digests")
                if not _is_real_text(value.get("name")):
                    errors.append(f"{path}.name must identify the evidence record")
                if value.get("solution") != solution_id:
                    errors.append(f"{path}.solution must match service.solution_id")
                if value.get("runtime") != runtime:
                    errors.append(f"{path}.runtime must match service.runtime")
                if runtime == "ansible" and value.get("underlying_runtime") != underlying_runtime:
                    errors.append(f"{path}.underlying_runtime must match service.underlying_runtime")
                if value.get("os_id") != os_id:
                    errors.append(f"{path}.os_id must match service.os_id")
                if value.get("release") != release_version:
                    errors.append(f"{path}.release must match release.version")
                if value.get("environment") != environment:
                    errors.append(f"{path}.environment must match service.environment")
                if (
                    not (path == "release" or path.startswith("release."))
                    and _deployment_target_complete(manifest)
                    and value.get("deployment_target") != manifest.get("deployment_target")
                ):
                    errors.append(f"{path}.deployment_target must match the approved production target")
                if runtime == "ansible" and value.get("execution_environment_digest") != execution_environment_digest:
                    errors.append(f"{path}.execution_environment_digest must match release.execution_environment.digest")
                if not (
                    (
                        isinstance(value.get("execution_environment"), str)
                        and value.get("execution_environment") in ENVIRONMENT_VALUES
                    )
                    or (
                        path == "release"
                        and _has_structured_release_execution_environment(value)
                    )
                ):
                    errors.append(f"{path}.execution_environment must explicitly identify a supported execution environment")
                recorded_at = _parse_timestamp(value.get("recorded_at"))
                if recorded_at is None:
                    errors.append(f"{path}.recorded_at must be a timezone-qualified RFC 3339 timestamp")
                elif recorded_at > current + APPROVAL_CLOCK_SKEW:
                    errors.append(f"{path}.recorded_at must not be future-dated")
                else:
                    freshness_limit = _evidence_max_age(path, manifest)
                    if freshness_limit is None:
                        errors.append(
                            f"{path}.recorded_at has no approved evidence freshness policy"
                        )
                    elif recorded_at < current - freshness_limit - APPROVAL_CLOCK_SKEW:
                        errors.append(
                            f"{path}.recorded_at exceeds the "
                            f"{_freshness_window_label(freshness_limit)} freshness window"
                        )
                if not _is_real_text(value.get("operator")):
                    errors.append(f"{path}.operator must identify the recording operator")
                if not _is_real_text(value.get("fixture_set")):
                    errors.append(f"{path}.fixture_set must identify the reviewed evidence fixture set")
            for key, child in value.items():
                visit(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(manifest, "")
    for evidence, references in sorted(evidence_references.items()):
        if len(references) > 1:
            errors.append(
                f"passing evidence file '{evidence}' is reused by multiple records: "
                + ", ".join(references)
            )
    return errors


def assess_readiness(manifest_path: Path, catalog: Catalog) -> dict[str, Any]:
    try:
        if has_symlink_component(manifest_path) or not manifest_path.is_file():
            raise OSError("readiness manifest must be a regular, non-symlink file")
        manifest_bytes, _ = _read_stable_bytes(
            manifest_path,
            max_bytes=MAX_READINESS_MANIFEST_BYTES,
        )
        manifest = load_json_document(manifest_bytes.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {
            "status": "fail",
            "score": 0,
            "max_score": 100,
            "manifest": str(manifest_path),
            "service": {},
            "release_version": None,
            "execution_environment_digest": None,
            "errors": [f"cannot read readiness manifest: {exc}"],
            "criteria": [],
            "gaps": ["Provide a readable JSON readiness manifest."],
        }

    errors = validate_manifest(manifest, catalog)
    root = manifest_path.parent
    manifest_data = manifest if isinstance(manifest, dict) else {}
    context = _evidence_context(manifest_data, root, catalog)
    if context is None:
        for error in _evidence_index_errors(manifest_data, root):
            if error not in errors:
                errors.append(error)
    release_for_controls = manifest_data.get("release")
    if isinstance(release_for_controls, dict) and release_for_controls.get("status") == "pass":
        for error in _github_controls_errors(
            release_for_controls.get("github_controls"),
            release_for_controls.get("source_repository"),
            release_for_controls.get("source_repository_id"),
            release_for_controls.get("source_revision"),
            manifest_data,
            root,
            context,
        ):
            message = f"release.github_controls {error}"
            if message not in errors:
                errors.append(message)
    recovery_for_signatures = manifest_data.get("recovery")
    if (
        isinstance(release_for_controls, dict)
        and release_for_controls.get("status") == "pass"
    ) or (
        isinstance(recovery_for_signatures, dict)
        and recovery_for_signatures.get("status") == "pass"
    ):
        if _trusted_cosign_binary() is None:
            errors.append("signature verification requires a controller-pinned Cosign executable")
        if _trusted_file_bytes(
            "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_PATH",
            "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_SHA256",
            MAX_SIGSTORE_TRUSTED_ROOT_BYTES,
            "Sigstore trusted root",
        ) is None:
            errors.append("signature verification requires a controller-pinned Sigstore trusted root")
        if _signing_policy(manifest_data) is None:
            errors.append("signature verification requires a controller-pinned signing policy")
    criteria: list[dict[str, Any]] = []
    score = 0
    for code, label, points, check in CRITERIA:
        # Score independent domains even when another section is malformed;
        # the final status remains fail until both validation and all criteria
        # pass. This gives operators a useful gap report instead of hiding
        # every completed control behind the first invalid field.
        passed = check(manifest_data, root, context)
        if passed:
            score += points
        criteria.append({"code": code, "label": label, "points": points if passed else 0, "max_points": points, "status": "pass" if passed else "fail"})
    gaps = [item["label"] for item in criteria if item["status"] != "pass"]
    release_section = manifest_data.get("release")
    execution_environment = release_section.get("execution_environment") if isinstance(release_section, dict) else None
    return {
        "status": "pass" if score == 100 and not errors else "fail",
        "score": score,
        "max_score": 100,
        "manifest": str(manifest_path),
        "service": manifest_data.get("service", {}),
        "release_version": release_section.get("version") if isinstance(release_section, dict) else None,
        "execution_environment_digest": execution_environment.get("digest") if isinstance(execution_environment, dict) else None,
        "errors": errors,
        "criteria": criteria,
        "gaps": gaps,
    }
