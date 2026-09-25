#!/usr/bin/env python3
"""Check a separately approved, short-lived first staging apply authorization.

The controller protects the digest of the authorization object independently of
the full readiness manifest digest. This verifier binds that authorization to
the exact release, controller image, provider content, and Kubernetes target.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from archiveweaver.evidence import _read_stable_bytes  # noqa: E402
from archiveweaver.json_utils import load_json_document  # noqa: E402
from archiveweaver.path_utils import has_symlink_component  # noqa: E402


MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_AUTHORIZATION_LIFETIME = timedelta(hours=24)
AUTHORIZATION_KEYS = frozenset(
    {
        "schema_version",
        "purpose",
        "service",
        "release_version",
        "source_repository",
        "source_repository_id",
        "source_revision",
        "execution_environment_digest",
        "provider_bundle_digest",
        "kustomize_bundle_sha256",
        "kubeconfig_sha256",
        "inventory_sha256",
        "kube_context",
        "namespace",
        "change_ticket",
        "approval_ticket",
        "approved_by",
        "issued_at",
        "expires_at",
    }
)
SERVICE_KEYS = frozenset(
    {"solution_id", "runtime", "underlying_runtime", "os_id", "environment"}
)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OCI_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
TICKET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,63}\Z")
KUBE_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:-]{0,252}\Z")
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _real_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and value == value.strip()
        and not re.search(r"REPLACE|PLACEHOLDER|EXAMPLE|CHANGEME|TODO", value, re.IGNORECASE)
        and not any(ord(character) < 32 for character in value)
    )


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def authorization_digest(authorization: dict[str, Any]) -> str:
    """Hash the canonical JSON object, not formatting in the manifest file."""
    canonical = json.dumps(
        authorization,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_authorization(
    manifest: Any,
    expected_digest: str,
    source_revision: str,
    execution_environment_digest: str,
    provider_bundle_digest: str,
    kustomize_bundle_sha256: str,
    kubeconfig_sha256: str,
    inventory_sha256: str,
    kube_context: str,
    namespace: str,
    change_ticket: str,
    approval_ticket: str,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Return fail-closed reasons without emitting manifest or credential bytes."""
    bindings = (
        (expected_digest, HEX_SHA256, "authorization digest"),
        (source_revision, GIT_SHA, "source revision"),
        (execution_environment_digest, OCI_SHA256, "execution environment digest"),
        (provider_bundle_digest, OCI_SHA256, "provider bundle digest"),
        (kustomize_bundle_sha256, HEX_SHA256, "Kustomize bundle digest"),
        (kubeconfig_sha256, HEX_SHA256, "kubeconfig digest"),
        (inventory_sha256, HEX_SHA256, "inventory digest"),
        (kube_context, KUBE_CONTEXT, "Kubernetes context"),
        (namespace, NAMESPACE, "namespace"),
        (change_ticket, TICKET, "change ticket"),
        (approval_ticket, TICKET, "approval ticket"),
    )
    for value, pattern, name in bindings:
        if pattern.fullmatch(value) is None or not _real_text(value):
            return [f"invalid {name} binding"]
    if change_ticket == approval_ticket:
        return ["approval ticket must be independent of the change ticket"]
    if not isinstance(manifest, dict):
        return ["readiness manifest must be an object"]
    authorization = manifest.get("staging_seed_authorization")
    if not isinstance(authorization, dict) or set(authorization) != AUTHORIZATION_KEYS:
        return ["staging seed authorization is missing or has an invalid shape"]
    if authorization_digest(authorization) != expected_digest:
        return ["staging seed authorization does not match the protected digest"]
    if (
        type(authorization.get("schema_version")) is not int
        or authorization.get("schema_version") != 1
        or authorization.get("purpose") != "first-staging-apply"
    ):
        return ["staging seed authorization purpose or schema is invalid"]

    service = _object(manifest.get("service"))
    authorized_service = authorization.get("service")
    if (
        not isinstance(authorized_service, dict)
        or set(authorized_service) != SERVICE_KEYS
        or authorized_service != {key: service.get(key) for key in SERVICE_KEYS}
        or authorized_service.get("solution_id") != "paperless-ngx"
        or authorized_service.get("runtime") != "ansible"
        or authorized_service.get("underlying_runtime") != "rke2"
        or authorized_service.get("environment") != "staging"
        or not _real_text(authorized_service.get("os_id"))
    ):
        return ["staging seed service identity does not match the staging target"]

    release = _object(manifest.get("release"))
    provider = _object(release.get("provider_bundle"))
    execution_environment = _object(release.get("execution_environment"))
    control = _object(manifest.get("control"))
    governance = _object(manifest.get("governance"))
    required_equalities: tuple[tuple[str, Any], ...] = (
        ("release_version", release.get("version")),
        ("source_repository", release.get("source_repository")),
        ("source_repository_id", release.get("source_repository_id")),
        ("source_revision", release.get("source_revision")),
        ("source_revision", source_revision),
        ("execution_environment_digest", execution_environment.get("digest")),
        ("execution_environment_digest", execution_environment_digest),
        ("provider_bundle_digest", provider.get("digest")),
        ("provider_bundle_digest", provider_bundle_digest),
        ("kustomize_bundle_sha256", kustomize_bundle_sha256),
        ("kubeconfig_sha256", kubeconfig_sha256),
        ("inventory_sha256", inventory_sha256),
        ("kube_context", kube_context),
        ("namespace", namespace),
        ("change_ticket", control.get("change_ticket")),
        ("change_ticket", governance.get("change_ticket")),
        ("change_ticket", change_ticket),
        ("approval_ticket", approval_ticket),
        ("approved_by", governance.get("approved_by")),
    )
    for key, value in required_equalities:
        if authorization.get(key) != value:
            return [f"staging seed authorization {key} does not match the protected release or job"]
    source_repository = authorization.get("source_repository")
    if (
        not _real_text(authorization.get("release_version"))
        or not isinstance(source_repository, str)
        or REPOSITORY.fullmatch(source_repository) is None
        or type(authorization.get("source_repository_id")) is not int
        or authorization["source_repository_id"] <= 0
        or not _real_text(authorization.get("approved_by"))
        or authorization.get("approved_by") == control.get("operator")
        or not _real_text(authorization.get("change_ticket"))
        or not _real_text(authorization.get("approval_ticket"))
        or provider.get("remote_digest") != f"sha256:{kustomize_bundle_sha256}"
    ):
        return ["staging seed authorization release identity is invalid"]

    issued_at = _timestamp(authorization.get("issued_at"))
    expires_at = _timestamp(authorization.get("expires_at"))
    governance_approved_at = _timestamp(governance.get("approved_at"))
    governance_valid_until = _timestamp(governance.get("valid_until"))
    current_time = now or datetime.now(timezone.utc)
    if (
        issued_at is None
        or expires_at is None
        or governance_approved_at is None
        or governance_valid_until is None
        or current_time.tzinfo is None
        or issued_at < governance_approved_at
        or expires_at > governance_valid_until
        or not issued_at <= current_time < expires_at
        or expires_at - issued_at > MAX_AUTHORIZATION_LIFETIME
    ):
        return ["staging seed authorization is expired, premature, or too long-lived"]
    return []


def main(argv: list[str]) -> int:
    if len(argv) != 14:
        print(
            "usage: verify-staging-seed-authorization.py <manifest> <manifest-sha256> "
            "<authorization-sha256> "
            "<source-sha> <execution-environment-digest> <provider-bundle-digest> "
            "<kustomize-sha256> <kubeconfig-sha256> <inventory-sha256> <kube-context> <namespace> "
            "<change-ticket> <approval-ticket>",
            file=sys.stderr,
        )
        return 2
    manifest_path = Path(argv[1])
    if HEX_SHA256.fullmatch(argv[2]) is None:
        print("protected readiness manifest digest is invalid", file=sys.stderr)
        return 2
    if has_symlink_component(manifest_path) or not manifest_path.is_file():
        print("readiness manifest must be a regular, non-symlink file", file=sys.stderr)
        return 1
    try:
        resolved = manifest_path.resolve()
        resolved.relative_to(REPOSITORY_ROOT.resolve())
        raw, measured_digest = _read_stable_bytes(resolved, max_bytes=MAX_MANIFEST_BYTES)
        if measured_digest != argv[2]:
            print("readiness manifest does not match the protected digest", file=sys.stderr)
            return 1
        manifest = load_json_document(raw.decode("utf-8", errors="strict"))
    except (OSError, RuntimeError, ValueError, UnicodeDecodeError):
        print("readiness manifest is invalid or outside the signed checkout", file=sys.stderr)
        return 1
    errors = validate_authorization(manifest, *argv[3:])
    if errors:
        print(errors[0], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
