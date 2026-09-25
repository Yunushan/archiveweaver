#!/usr/bin/env python3
"""Require exact OCI image coverage between a rendered provider and a release manifest.

The controller runs this after the readiness manifest has passed its signature,
SBOM, provenance, and approved-manifest checks. This script verifies the remaining
provider-to-release binding; a digest-shaped image reference alone is not proof.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from archiveweaver.evidence import _read_stable_bytes  # noqa: E402
from archiveweaver.json_utils import load_json_document  # noqa: E402
from archiveweaver.path_utils import has_symlink_component  # noqa: E402

try:
    import yaml
except ImportError:  # Give the controller a deterministic failure, not a traceback.
    yaml = None  # type: ignore[assignment]


MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 16 * 1024 * 1024
MAX_DOCUMENTS = 1000
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME_SEGMENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
REGISTRY_SEGMENT = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]*)?\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
PLACEHOLDER = re.compile(r"example\.invalid|replace|todo|tbd|latest", re.IGNORECASE)
RUNTIMES = frozenset({"kubernetes", "docker", "docker-swarm"})


class InvalidInput(ValueError):
    """Malformed invocation, manifest, or provider model (exit 2)."""


class CoverageFailure(ValueError):
    """A rendered image lacks exact approved release coverage (exit 1)."""


def _manifest_images(raw: bytes) -> set[str]:
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise InvalidInput("approved manifest is empty or exceeds its size limit")
    try:
        manifest = load_json_document(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        if str(exc).startswith("duplicate JSON object key"):
            raise InvalidInput("approved manifest has duplicate JSON keys") from exc
        raise InvalidInput("approved manifest is not valid, finite, bounded UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("release"), dict):
        raise InvalidInput("approved manifest is missing its release section")
    artifacts = manifest["release"].get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise InvalidInput("approved manifest is missing release artifacts")

    images: set[str] = set()
    for index, row in enumerate(artifacts):
        if not isinstance(row, dict):
            raise InvalidInput(f"release artifact {index} is not an object")
        if "image" not in row:
            continue  # Package artifacts can coexist with OCI image artifacts.
        ref = row["image"]
        if not isinstance(ref, str) or not _immutable_image(ref):
            raise CoverageFailure(f"release artifact {index} has an invalid OCI image reference")
        if row.get("digest") != ref.split("@", 1)[1]:
            raise CoverageFailure(f"release artifact {index} image and artifact digests differ")
        if ref in images:
            raise CoverageFailure("release artifacts contain a duplicate OCI image reference")
        images.add(ref)
    if not images:
        raise CoverageFailure("release artifacts contain no approved OCI image references")
    return images


def _immutable_image(ref: str) -> bool:
    if not ref or PLACEHOLDER.search(ref) or ref.count("@") != 1:
        return False
    repository, digest = ref.split("@", 1)
    if not IMAGE_DIGEST.fullmatch(digest):
        return False
    segments = repository.split("/")
    if len(segments) < 2 or REGISTRY_SEGMENT.fullmatch(segments[0]) is None:
        return False
    registry = segments[0]
    host, separator, port = registry.rpartition(":")
    if separator:
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            return False
    else:
        host = registry
    labels = host.split(".")
    if (not separator and host != "localhost" and len(labels) < 2) or any(
        DNS_LABEL.fullmatch(label) is None for label in labels
    ):
        return False
    return all(NAME_SEGMENT.fullmatch(segment) for segment in segments[1:])


if yaml is not None:
    class _StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise InvalidInput("rendered model must not contain YAML aliases")
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
            if not isinstance(node, yaml.MappingNode):
                raise InvalidInput("rendered model has an invalid YAML mapping")
            mapping: dict[Any, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise InvalidInput("rendered model has a non-string YAML mapping key")
                if key in mapping:
                    raise InvalidInput("rendered model has duplicate YAML mapping keys")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping


def _load_yaml(raw: bytes) -> list[Any]:
    if yaml is None:
        raise InvalidInput("PyYAML is required in the controller execution environment")
    if not raw or len(raw) > MAX_MODEL_BYTES:
        raise InvalidInput("rendered provider model is empty or exceeds its size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        documents: list[Any] = []
        for document in yaml.load_all(text, Loader=_StrictLoader):
            if len(documents) >= MAX_DOCUMENTS:
                raise InvalidInput("rendered provider model exceeds its document limit")
            documents.append(document)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidInput("rendered provider model is not valid, unambiguous UTF-8 YAML") from exc
    if not documents or any(not isinstance(doc, dict) for doc in documents):
        raise InvalidInput("rendered provider model must contain nonempty YAML objects")
    return documents


def _image_key_count(value: Any) -> int:
    pending = [value]
    count = 0
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            count += sum(key == "image" for key in current)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return count


def _containers(pod_spec: Any, resource: str) -> list[str]:
    if not isinstance(pod_spec, dict):
        raise CoverageFailure(f"{resource} has no pod specification")
    primary = pod_spec.get("containers")
    if not isinstance(primary, list) or not primary:
        raise CoverageFailure(f"{resource} has no containers")
    images: list[str] = []
    names: set[str] = set()
    for field in ("containers", "initContainers", "ephemeralContainers"):
        entries = pod_spec.get(field, [] if field != "containers" else None)
        if not isinstance(entries, list):
            raise CoverageFailure(f"{resource} has an invalid {field} list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise CoverageFailure(f"{resource} has a non-object container")
            name = entry.get("name")
            ref = entry.get("image")
            if not isinstance(name, str) or not name or name in names:
                raise CoverageFailure(f"{resource} has a missing or duplicate container name")
            if not isinstance(ref, str) or not _immutable_image(ref):
                raise CoverageFailure(f"{resource} container {name} has a missing or mutable image")
            names.add(name)
            images.append(ref)
    return images


def _nested(value: Any, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _kubernetes_images(documents: list[Any]) -> set[str]:
    pod_paths: dict[tuple[str, str], tuple[str, ...]] = {
        ("v1", "Pod"): ("spec",),
        ("v1", "ReplicationController"): ("spec", "template", "spec"),
        **{("apps/v1", kind): ("spec", "template", "spec") for kind in (
            "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"
        )},
        ("batch/v1", "Job"): ("spec", "template", "spec"),
        ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
    }
    safe_nonworkloads = {
        *(('v1', kind) for kind in (
            'ConfigMap', 'Endpoints', 'LimitRange', 'Namespace', 'PersistentVolume',
            'PersistentVolumeClaim', 'ResourceQuota', 'Secret', 'Service', 'ServiceAccount',
        )),
        *(('networking.k8s.io/v1', kind) for kind in ('Ingress', 'IngressClass', 'NetworkPolicy')),
        ('policy/v1', 'PodDisruptionBudget'),
        *(('rbac.authorization.k8s.io/v1', kind) for kind in (
            'ClusterRole', 'ClusterRoleBinding', 'Role', 'RoleBinding',
        )),
        ('autoscaling/v2', 'HorizontalPodAutoscaler'),
        ('storage.k8s.io/v1', 'StorageClass'),
    }
    images: set[str] = set()
    identities: set[tuple[str, str, str, str]] = set()
    workload_count = 0
    for document in documents:
        api_version = document.get("apiVersion")
        kind = document.get("kind")
        metadata = document.get("metadata")
        if not isinstance(api_version, str) or not api_version or not isinstance(kind, str) or not kind:
            raise InvalidInput("rendered Kubernetes resource lacks apiVersion or kind")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str) or not metadata["name"]:
            raise InvalidInput("rendered Kubernetes resource lacks metadata.name")
        namespace = metadata.get("namespace", "")
        if not isinstance(namespace, str):
            raise InvalidInput("rendered Kubernetes resource has an invalid namespace")
        identity = (api_version, kind, namespace, metadata["name"])
        if identity in identities:
            raise InvalidInput("rendered Kubernetes model has duplicate resources")
        identities.add(identity)
        pod_path = pod_paths.get((api_version, kind))
        if pod_path is None:
            if _image_key_count(document):
                raise CoverageFailure(f"unsupported image-bearing Kubernetes resource {kind}")
            if (api_version, kind) not in safe_nonworkloads:
                raise CoverageFailure(f"unrecognized Kubernetes resource {api_version}/{kind}")
            continue
        workload_count += 1
        resource = f"{kind}/{metadata['name']}"
        refs = _containers(_nested(document, pod_path), resource)
        if _image_key_count(document) != len(refs):
            raise CoverageFailure(f"{resource} has an image field outside its container lists")
        images.update(refs)
    if not workload_count:
        raise CoverageFailure("rendered Kubernetes model contains no supported workloads")
    return images


def _compose_images(documents: list[Any]) -> set[str]:
    if len(documents) != 1:
        raise InvalidInput("rendered Compose model must contain exactly one document")
    model = documents[0]
    if any(key not in {"name", "version", "services", "networks", "volumes", "secrets", "configs"}
           for key in model):
        raise CoverageFailure("rendered Compose model has unsupported top-level directives")
    services = model.get("services")
    if not isinstance(services, dict) or not services:
        raise CoverageFailure("rendered Compose model has no services")
    images: set[str] = set()
    for name, service in services.items():
        if not isinstance(name, str) or not name or not isinstance(service, dict):
            raise InvalidInput("rendered Compose model has an invalid service")
        if any(key in service for key in ("build", "develop", "extends", "include")) or service.get("pull_policy") == "build":
            raise CoverageFailure(f"Compose service {name} contains a build-capable or unresolved directive")
        ref = service.get("image")
        if not isinstance(ref, str) or not _immutable_image(ref):
            raise CoverageFailure(f"Compose service {name} has a missing or mutable image")
        if _image_key_count(service) != 1:
            raise CoverageFailure(f"Compose service {name} has an image field outside its service image")
        images.add(ref)
    if _image_key_count(model) != len(services):
        raise CoverageFailure("rendered Compose model has image fields outside services")
    return images


def verify(manifest_bytes: bytes, runtime: str, model_bytes: bytes) -> None:
    if runtime not in RUNTIMES:
        raise InvalidInput("unsupported provider runtime")
    approved = _manifest_images(manifest_bytes)
    documents = _load_yaml(model_bytes)
    deployed = _kubernetes_images(documents) if runtime == "kubernetes" else _compose_images(documents)
    if deployed != approved:
        missing = len(deployed - approved)
        unused = len(approved - deployed)
        raise CoverageFailure(
            f"rendered provider image coverage differs from approved release artifacts "
            f"({missing} unapproved, {unused} unused)"
        )


def _read_manifest(path_string: str, expected_digest: str) -> bytes:
    path = Path(path_string)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise InvalidInput("approved manifest SHA-256 must be 64 lowercase hex characters")
    if not path.is_absolute() or has_symlink_component(path):
        raise InvalidInput("approved manifest path must be absolute and contain no symlinks")
    try:
        content, observed_digest = _read_stable_bytes(path, max_bytes=MAX_MANIFEST_BYTES)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidInput("approved manifest cannot be read as a stable regular file") from exc
    if observed_digest != expected_digest:
        raise CoverageFailure("approved manifest bytes no longer match the protected SHA-256")
    return content


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[2] not in RUNTIMES:
        print(
            "usage: verify-provider-image-coverage.py <approved-manifest-absolute-path> "
            "<kubernetes|docker|docker-swarm> <approved-manifest-sha256> < rendered-model.yaml",
            file=sys.stderr,
        )
        return 2
    try:
        model = sys.stdin.buffer.read(MAX_MODEL_BYTES + 1)
        verify(_read_manifest(argv[1], argv[3]), argv[2], model)
    except InvalidInput as exc:
        print(f"provider image coverage input invalid: {exc}", file=sys.stderr)
        return 2
    except CoverageFailure as exc:
        print(f"provider image coverage rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
