from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .catalog import Catalog
from .evidence import verify_evidence_index
from .json_utils import load_json_document
from .path_utils import has_symlink_component


PLACEHOLDER_RE = re.compile(r"(?:replace|todo|tbd|example\.invalid|latest)", re.IGNORECASE)
WINDOWS_ABSOLUTE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]{2})")
RFC3339_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
IN_TOTO_STATEMENT_RE = re.compile(r"^https://in-toto\.io/Statement/v[0-9]+(?:\.[0-9]+)?$")
SPDX_VERSION_RE = re.compile(r"^SPDX-[0-9]+\.[0-9]+$")
CYCLONEDX_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
OCI_IMAGE_DIGEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$")
STATUS_VALUES = {"pass", "pending", "fail"}
ENVIRONMENT_VALUES = {"production", "staging", "restore", "dr"}
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "service",
    "evidence_index",
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
EvidenceContext = tuple[Path, frozenset[str], Catalog]
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


def _is_real_timestamp(value: Any) -> bool:
    """Accept only timezone-qualified RFC 3339 timestamps for audit fields."""
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


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


def _indexed(candidate: Path | None, context: EvidenceContext | None) -> bool:
    if candidate is None or context is None:
        return False
    bundle_root, indexed_files, _ = context
    try:
        relative = candidate.relative_to(bundle_root).as_posix()
    except ValueError:
        return False
    return relative in indexed_files


def _evidence_exists(value: Any, root: Path, context: EvidenceContext | None) -> bool:
    if not isinstance(value, dict) or value.get("status") != "pass":
        return False
    evidence = value.get("evidence")
    return _indexed(_relative_candidate(evidence, root), context)


def _evidence_metadata_matches(value: Any, manifest: dict[str, Any]) -> bool:
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
            runtime != "ansible"
            or value.get("execution_environment_digest") == execution_environment_digest
        )
        and (
            "execution_environment" not in value
            or (
                isinstance(value.get("execution_environment"), str)
                and value.get("execution_environment") in ENVIRONMENT_VALUES
            )
            or _has_structured_release_execution_environment(value)
        )
        and _is_real_timestamp(value.get("recorded_at"))
        and _is_real_text(value.get("operator"))
        and _is_real_text(value.get("fixture_set"))
    )


def _evidence_payload_matches(value: Any, root: Path, context: EvidenceContext | None, manifest: dict[str, Any]) -> bool:
    payload = _json_evidence_payload(value, root, context)
    if payload is None:
        candidate = _relative_candidate(value.get("evidence"), root) if isinstance(value, dict) else None
        return candidate is not None and candidate.suffix.lower() != ".json" and _indexed(candidate, context)
    return bool(
        payload.get("status") == "pass"
        and isinstance(value, dict)
        and payload.get("name") == value.get("name")
        and payload.get("evidence") == value.get("evidence")
        and _evidence_metadata_matches(payload, manifest)
    )


def _json_evidence_payload(value: Any, root: Path, context: EvidenceContext | None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    candidate = _relative_candidate(value.get("evidence"), root)
    if candidate is None or not _indexed(candidate, context) or candidate.suffix.lower() != ".json":
        return None
    try:
        payload = load_json_document(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _evidence_record_exists(value: Any, root: Path, context: EvidenceContext | None, manifest: dict[str, Any]) -> bool:
    return (
        _evidence_exists(value, root, context)
        and _evidence_metadata_matches(value, manifest)
        and _evidence_payload_matches(value, root, context, manifest)
    )


def _relative_file(value: Any, root: Path, context: EvidenceContext | None) -> bool:
    # A referenced artifact, detached signature, or runbook must contain
    # content; an indexed zero-byte placeholder is not operational proof.
    candidate = _relative_candidate(value, root)
    if candidate is None or not _indexed(candidate, context):
        return False
    try:
        return candidate.stat().st_size > 0
    except OSError:
        return False


def _path_identity(value: Any) -> str | None:
    """Return a normalized relative spelling for cross-field path checks."""
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(value).as_posix()


def _artifact_proof_paths(value: Any) -> set[str]:
    """Return the artifact, SBOM, and detached-signature path identities."""
    if not isinstance(value, dict):
        return set()
    paths = {
        _path_identity(value.get(field))
        for field in ("path", "sbom", "signature")
    }
    return {path for path in paths if path is not None}


def _execution_environment_proof_paths(value: Any) -> set[str]:
    """Return the controller-image attestation, SBOM, and signature paths."""
    if not isinstance(value, dict):
        return set()
    paths = {
        _path_identity(value.get(field))
        for field in ("provenance", "sbom", "signature")
    }
    return {path for path in paths if path is not None}


def _release_proof_paths(value: Any) -> set[str]:
    """Return every local proof path owned by a release section."""
    if not isinstance(value, dict):
        return set()
    paths: set[str] = set()
    artifacts = value.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            paths.update(_artifact_proof_paths(artifact))
    paths.update(_artifact_proof_paths(value.get("provider_bundle")))
    paths.update(_execution_environment_proof_paths(value.get("execution_environment")))
    return paths


def _structured_json_payload(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    required_groups: tuple[tuple[str, ...], ...],
) -> dict[str, Any] | None:
    """Require an indexed JSON attestation with meaningful grouped content."""
    candidate = _relative_candidate(value, root)
    if candidate is None or not _indexed(candidate, context) or candidate.suffix.lower() != ".json":
        return None
    try:
        payload = load_json_document(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
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


def _meaningful_component_list(value: Any) -> bool:
    identity_keys = ("name", "SPDXID", "bom-ref", "purl", "group")
    return isinstance(value, list) and any(
        isinstance(component, dict)
        and any(_is_real_text(component.get(identity)) for identity in identity_keys)
        for component in value
    )


def _sbom_payload(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
) -> dict[str, Any] | None:
    payload = _structured_json_payload(value, root, context, SBOM_GROUPS)
    if payload is None:
        return None
    if (
        isinstance(payload.get("spdxVersion"), str)
        and SPDX_VERSION_RE.fullmatch(payload["spdxVersion"])
        and _meaningful_component_list(payload.get("packages"))
    ):
        return payload
    if (
        payload.get("bomFormat") == "CycloneDX"
        and isinstance(payload.get("specVersion"), str)
        and CYCLONEDX_VERSION_RE.fullmatch(payload["specVersion"])
        and _meaningful_component_list(payload.get("components"))
    ):
        return payload
    return None


def _sbom_file(value: Any, root: Path, context: EvidenceContext | None) -> bool:
    return _sbom_payload(value, root, context) is not None


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
    components = payload.get("packages") if "packages" in payload else payload.get("components")
    if not isinstance(components, list):
        return False
    identity_keys = ("name", "SPDXID", "bom-ref", "purl", "group")
    return any(
        isinstance(component, dict)
        and any(component.get(key) == expected_name for key in identity_keys)
        for component in components
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
    if not (
        isinstance(statement_type, str)
        and IN_TOTO_STATEMENT_RE.fullmatch(statement_type)
        and _is_real_text(payload.get("predicateType"))
    ):
        return None
    return payload


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
    return bool(payload) and bool(expected) and expected <= _attestation_subject_digests(payload)


def _provenance_binds_subjects(payload: dict[str, Any] | None, expected: set[tuple[str, str]]) -> bool:
    return bool(payload) and bool(expected) and expected <= _attestation_subject_bindings(payload)


PROVENANCE_GROUPS = (("subject",), ("predicateType", "buildType", "payloadType", "materials"))
SBOM_GROUPS = (("spdxVersion", "bomFormat"), ("packages", "components"))


def _digest_matches(value: Any, digest: str, root: Path, context: EvidenceContext | None) -> bool:
    if not _relative_file(value, root, context) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return False
    candidate = (root / str(value)).resolve()
    hasher = hashlib.sha256()
    try:
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        return False
    return f"sha256:{hasher.hexdigest()}" == digest


def _signed_artifact_ok(
    value: Any,
    root: Path,
    context: EvidenceContext | None,
    manifest: dict[str, Any],
) -> bool:
    """Verify one release or rollback artifact and its detached proof."""
    if not isinstance(value, dict):
        return False
    digest = str(value.get("digest", ""))
    referenced_paths = [
        _path_identity(value.get("path")),
        _path_identity(value.get("sbom")),
        _path_identity(value.get("signature")),
    ]
    if not (
        all(path is not None for path in referenced_paths)
        and len(set(referenced_paths)) == len(referenced_paths)
        and _is_real_text(value.get("name"))
        and _digest_matches(value.get("path"), digest, root, context)
        and _sbom_binds_name(value.get("sbom"), str(value.get("name", "")), root, context)
        and _relative_file(value.get("signature"), root, context)
        and value.get("signature_verified") is True
        and _evidence_record_exists(value.get("signature_verification"), root, context, manifest)
    ):
        return False
    signature_payload = _json_evidence_payload(value.get("signature_verification"), root, context)
    return bool(
        isinstance(signature_payload, dict)
        and signature_payload.get("artifact_digest") == digest
        and _is_real_text(signature_payload.get("verifier"))
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
    provenance_payload = _provenance_payload(value.get("provenance"), root, context)
    if (
        not _is_real_text(value.get("name"))
        or value.get("provenance_verified") is not True
        or provenance_payload is None
        or not _provenance_binds_digests(provenance_payload, {digest})
        or not _provenance_binds_subjects(provenance_payload, {(str(value.get("name", "")), digest)})
        or not _sbom_binds_name(value.get("sbom"), str(value.get("name", "")), root, context)
        or not _relative_file(value.get("signature"), root, context)
        or value.get("signature_verified") is not True
        or not _evidence_record_exists(value.get("signature_verification"), root, context, manifest)
    ):
        return False
    verification_payload = _json_evidence_payload(value.get("signature_verification"), root, context)
    return bool(
        isinstance(verification_payload, dict)
        and verification_payload.get("artifact_digest") == digest
        and _is_real_text(verification_payload.get("verifier"))
    )


def _evidence_context(manifest: dict[str, Any], root: Path, catalog: Catalog) -> EvidenceContext | None:
    index_path = _relative_candidate(manifest.get("evidence_index"), root)
    if index_path is None:
        return None
    report = verify_evidence_index(index_path)
    if report.get("status") != "pass":
        return None
    try:
        index = load_json_document(index_path.read_text(encoding="utf-8"))
        indexed_files = frozenset(entry["path"] for entry in index["files"] if isinstance(entry, dict) and isinstance(entry.get("path"), str))
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError):
        return None
    return index_path.parent.resolve(), indexed_files, catalog


def _evidence_index_errors(manifest: dict[str, Any], root: Path) -> list[str]:
    index_path = _relative_candidate(manifest.get("evidence_index"), root)
    if index_path is None:
        return ["evidence_index must identify a readable relative SHA-256 index file"]
    report = verify_evidence_index(index_path)
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
) -> bool:
    if not isinstance(values, list) or not values:
        return False
    if not all(
        isinstance(item, dict)
        and _is_real_text(item.get("name"))
        and (_evidence_exists(item, root, context) if manifest is None else _evidence_record_exists(item, root, context, manifest))
        for item in values
    ):
        return False
    names = [str(item["name"]).lower() for item in values]
    evidence_paths = [str(item["evidence"]) for item in values]
    return (
        (not required_names or {name.lower() for name in required_names} <= set(names))
        and len(set(names)) == len(values)
        and len(set(evidence_paths)) == len(values)
    )


def _section_pass(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") == "pass"


def _section_evidence_ok(section: Any, root: Path, context: EvidenceContext | None, manifest: dict[str, Any]) -> bool:
    return _section_pass(section) and _evidence_record_exists(section, root, context, manifest)


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
    if not all(_evidence_record_exists(record, root, context, manifest) for record in records):
        return False
    evidence_paths = [str(record["evidence"]) for record in records if isinstance(record, dict)]
    names = [str(record["name"]).lower() for record in records if isinstance(record, dict)]
    return len(set(evidence_paths)) == len(records) and len(set(names)) == len(records)


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
    if not (_section_pass(left_section) and _section_pass(right_section)):
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
    return bool(
        context is not None
        and _section_evidence_ok(section, root, context, manifest)
        and section.get("catalog_validated") is True
        and section.get("ci_green") is True
        and _is_real_text(section.get("change_ticket"))
        and _change_control_binding_ok(manifest)
    )


def _release_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("release")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    provenance_payload = _provenance_payload(
        section.get("provenance") if isinstance(section, dict) else None,
        root,
        context,
    )
    if (
        not _is_real_text(section.get("version"))
        or section.get("provenance_verified") is not True
        or provenance_payload is None
    ):
        return False
    artifacts = section.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False
    if not isinstance(artifacts, list) or not artifacts or not all(
        _signed_artifact_ok(item, root, context, manifest) for item in artifacts
    ):
        return False
    release_artifact_proof_paths: set[str] = set()
    for artifact in artifacts:
        artifact_paths = _artifact_proof_paths(artifact)
        if len(artifact_paths) != 3 or release_artifact_proof_paths.intersection(artifact_paths):
            return False
        release_artifact_proof_paths.update(artifact_paths)
    service = manifest.get("service")
    artifact_names = [str(item.get("name", "")) for item in artifacts if isinstance(item, dict)]
    artifact_paths = [str(item.get("path", "")) for item in artifacts if isinstance(item, dict)]
    if len(artifact_names) != len(set(artifact_names)) or len(artifact_paths) != len(set(artifact_paths)):
        return False
    expected_release_digests = {
        str(item.get("digest", "")) for item in artifacts if isinstance(item, dict)
    }
    expected_release_subjects = {
        (str(item.get("name", "")), str(item.get("digest", "")))
        for item in artifacts
        if isinstance(item, dict)
    }
    all_release_proof_paths = set(release_artifact_proof_paths)
    if isinstance(service, dict) and service.get("runtime") == "ansible":
        provider_bundle = section.get("provider_bundle")
        if isinstance(provider_bundle, dict):
            if str(provider_bundle.get("name", "")) in artifact_names:
                return False
            provider_paths = _artifact_proof_paths(provider_bundle)
            if len(provider_paths) != 3 or all_release_proof_paths.intersection(provider_paths):
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
        len(execution_environment_proof_paths) != 3
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
        and _signed_artifact_ok(provider_bundle, root, context, manifest)
        and _digest_matches(provider_bundle.get("path"), str(provider_bundle.get("digest", "")), root, context)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(provider_bundle.get("remote_digest", "")))
        and _evidence_record_exists(provider_bundle.get("verification"), root, context, manifest)
        and isinstance(provider_verification, dict)
        and provider_verification.get("artifact_digest") == provider_bundle.get("digest")
        and provider_verification.get("remote_digest") == provider_bundle.get("remote_digest")
        and _is_real_text(provider_verification.get("verifier"))
        and _execution_environment_ok(execution_environment, root, context, manifest)
    )


def _product_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("product_certification")
    if not _section_evidence_ok(section, root, context, manifest) or context is None:
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
        and _all_pass_with_evidence(section.get("test_matrix"), root, context, {"dependencies", "smoke", "migration", "formats", "api"}, manifest)
    )


def _resilience_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("resilience")
    return bool(
        _section_evidence_ok(section, root, context, manifest)
        and section.get("quorum_verified") is True
        and section.get("fencing_verified") is True
        and isinstance(section.get("failure_tests"), list)
        and len(section["failure_tests"]) >= 4
        and _all_pass_with_evidence(section.get("failure_tests"), root, context, {"node", "service", "dependency", "storage"}, manifest)
    )


def _data_protection_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("data_protection")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    backup = section.get("backup")
    restore = section.get("restore_test")
    fixity = section.get("fixity_test")
    return bool(
        isinstance(backup, dict)
        and type(backup.get("immutable_copies")) is int
        and backup.get("immutable_copies", 0) >= 2
        and _evidence_record_exists(backup, root, context, manifest)
        and _evidence_record_exists(restore, root, context, manifest)
        and _evidence_record_exists(fixity, root, context, manifest)
        and type(section.get("rpo_minutes")) is int
        and section.get("rpo_minutes", 0) > 0
        and type(section.get("rto_minutes")) is int
        and section.get("rto_minutes", 0) > 0
        and _service_objectives_binding_ok(manifest)
    )


def _security_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("security")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    return bool(
        _claim_evidence_ok("security", section, root, context, manifest)
        and section.get("sbom_verified") is True
        and section.get("tls_verified") is True
        and _is_real_text(section.get("secrets_provider"))
        and _evidence_record_exists(section.get("vulnerability_scan"), root, context, manifest)
        and _evidence_record_exists(section.get("penetration_test"), root, context, manifest)
    )


def _observability_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("observability")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    return bool(
        _claim_evidence_ok("observability", section, root, context, manifest)
        and all(_is_real_text(section.get(key)) for key in ("metrics", "alerts", "dashboards", "on_call"))
        and _on_call_binding_ok(manifest)
        and _evidence_record_exists(section.get("alert_delivery_test"), root, context, manifest)
    )


def _recovery_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("recovery")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    release = manifest.get("release")
    current_release = release.get("version") if isinstance(release, dict) else None
    rollback_artifact = section.get("rollback_artifact")
    rollback_digest = str(section.get("rollback_artifact_digest", ""))
    return bool(
        _is_real_text(section.get("rollback_release"))
        and section.get("rollback_release") != current_release
        and re.fullmatch(r"sha256:[0-9a-f]{64}", rollback_digest)
        and isinstance(rollback_artifact, dict)
        and rollback_artifact.get("digest") == rollback_digest
        and _signed_artifact_ok(rollback_artifact, root, context, manifest)
        and _evidence_record_exists(section.get("rollback_test"), root, context, manifest)
        and _evidence_record_exists(section.get("repair_test"), root, context, manifest)
        and not _artifact_proof_paths(rollback_artifact).intersection(
            _release_proof_paths(release)
        )
    )


def _governance_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("governance")
    if not _section_evidence_ok(section, root, context, manifest):
        return False
    return bool(
        _is_real_text(section.get("change_ticket"))
        and _is_real_text(section.get("approved_by"))
        and _is_real_timestamp(section.get("approved_at"))
        and section.get("evidence_immutable") is True
        and section.get("evidence_access_logged") is True
        and type(section.get("evidence_retention_days")) is int
        and section.get("evidence_retention_days", 0) > 0
        and _change_control_binding_ok(manifest)
        and _evidence_record_exists(section.get("retention_control"), root, context, manifest)
        and _evidence_record_exists(section.get("risk_review"), root, context, manifest)
    )


def _support_ok(manifest: dict[str, Any], root: Path, context: EvidenceContext | None) -> bool:
    section = manifest.get("support")
    if not _section_evidence_ok(section, root, context, manifest):
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
    errors: list[str] = []
    errors.extend(f"missing top-level field '{field}'" for field in sorted(REQUIRED_TOP_LEVEL - set(manifest)))
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
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
        if solution is not None and selected_runtime in catalog.runtimes:
            support_level = solution["mode_support"].get(selected_runtime)
            if support_level == "not-recommended":
                errors.append(f"service runtime '{selected_runtime}' is not-recommended for {solution_id}")
            if support_level == "conditional" and service.get("conditional_design_approved") is not True:
                errors.append("service.conditional_design_approved must be true for a conditional product/runtime pairing")
        try:
            catalog.operating_system(str(service.get("os_id")))
        except ValueError:
            errors.append("service.os_id must identify an operating system in the catalog")
        if service.get("environment") not in ENVIRONMENT_VALUES:
            errors.append("service.environment must identify a supported target environment")
    release = manifest.get("release", {})
    if isinstance(release, dict) and not _is_real_text(release.get("version")):
        errors.append("release.version must be a non-placeholder pinned release")
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
        artifacts = release.get("artifacts")
        if isinstance(artifacts, list):
            artifact_names = [str(item.get("name", "")) for item in artifacts if isinstance(item, dict)]
            artifact_paths = [str(item.get("path", "")) for item in artifacts if isinstance(item, dict)]
            if len(artifact_names) != len(set(artifact_names)):
                errors.append("release.artifacts must not contain duplicate artifact names")
            if len(artifact_paths) != len(set(artifact_paths)):
                errors.append("release.artifacts must not contain duplicate artifact paths")
            if isinstance(service, dict) and service.get("runtime") == "ansible":
                provider_bundle = release.get("provider_bundle")
                if isinstance(provider_bundle, dict) and str(provider_bundle.get("name", "")) in artifact_names:
                    errors.append("release.provider_bundle.name must be distinct from release.artifacts names")
    for section_name in sorted(REQUIRED_TOP_LEVEL - {"schema_version", "service", "evidence_index"}):
        section = manifest.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"{section_name} must be an object")
        elif section.get("status") not in STATUS_VALUES:
            errors.append(f"{section_name}.status must be pass, pending, or fail")
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
    if solution is not None:
        errors.extend(_catalog_coverage_errors(manifest.get("product_certification"), solution))
    for key, value in _walk_keys(manifest):
        if key.lower() in {"password", "passwd", "secret", "token", "private_key", "client_secret"}:
            errors.append(f"secret-bearing field '{key}' is not allowed in a readiness manifest")
        if key.lower() in {"path", "sbom", "signature", "provenance", "evidence", "evidence_index"} and isinstance(value, str):
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


def _evidence_metadata_errors(manifest: dict[str, Any]) -> list[str]:
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
                    normalized_evidence = Path(evidence).as_posix()
                    evidence_references.setdefault(normalized_evidence, []).append(path or "<root>")
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
                if runtime == "ansible" and value.get("execution_environment_digest") != execution_environment_digest:
                    errors.append(f"{path}.execution_environment_digest must match release.execution_environment.digest")
                if (
                    "execution_environment" in value
                    and (
                        not (
                            isinstance(value.get("execution_environment"), str)
                            and value.get("execution_environment") in ENVIRONMENT_VALUES
                        )
                        and not _has_structured_release_execution_environment(value)
                    )
                ):
                    errors.append(f"{path}.execution_environment must identify a supported execution environment")
                if not _is_real_timestamp(value.get("recorded_at")):
                    errors.append(f"{path}.recorded_at must be a timezone-qualified RFC 3339 timestamp")
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
        manifest = load_json_document(manifest_path.read_text(encoding="utf-8"))
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
        errors.extend(_evidence_index_errors(manifest_data, root))
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
