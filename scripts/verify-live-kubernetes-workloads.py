#!/usr/bin/env python3
"""Compare every reviewed Kubernetes workload and image with the live namespace.

Usage: verify-live-kubernetes-workloads.py <namespace>
Stdin: {"rendered_yaml": "...", "live_json": <kubectl get ... -o json object>}
"""

from __future__ import annotations

import re
import sys
from collections.abc import Hashable
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from archiveweaver.json_utils import load_json_document  # noqa: E402

try:
    import yaml
except ImportError:  # Give the controller a deterministic failure.
    yaml = None  # type: ignore[assignment]


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_RENDERED_BYTES = 16 * 1024 * 1024
MAX_OBJECTS = 1000
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME_SEGMENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
REGISTRY_SEGMENT = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]*)?\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
PLACEHOLDER = re.compile(r"example\.invalid|replace|todo|tbd|latest", re.IGNORECASE)
POD_PATHS: dict[tuple[str, str], tuple[str, ...]] = {
    ("apps/v1", "Deployment"): ("spec", "template", "spec"),
    ("apps/v1", "StatefulSet"): ("spec", "template", "spec"),
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}
GENERATED_JOB_LABELS = {
    "batch.kubernetes.io/controller-uid": "uid",
    "controller-uid": "uid",
    "batch.kubernetes.io/job-name": "name",
    "job-name": "name",
}
SAFE_NONWORKLOADS = {
    *(("v1", kind) for kind in (
        "ConfigMap", "Endpoints", "LimitRange", "Namespace", "PersistentVolume",
        "PersistentVolumeClaim", "ResourceQuota", "Secret", "Service", "ServiceAccount",
    )),
    *(("networking.k8s.io/v1", kind) for kind in ("Ingress", "IngressClass", "NetworkPolicy")),
    ("policy/v1", "PodDisruptionBudget"),
    *(("rbac.authorization.k8s.io/v1", kind) for kind in (
        "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    )),
    ("autoscaling/v2", "HorizontalPodAutoscaler"),
    ("storage.k8s.io/v1", "StorageClass"),
}


class InvalidInput(ValueError):
    """The invocation or an input document is malformed (exit 2)."""


class WorkloadMismatch(ValueError):
    """The live namespace differs from the reviewed workload model (exit 1)."""


if yaml is not None:
    class _StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise InvalidInput("rendered YAML must not contain aliases")
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Hashable, Any]:
            if not isinstance(node, yaml.MappingNode):
                raise InvalidInput("rendered YAML has an invalid mapping")
            result: dict[Hashable, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise InvalidInput("rendered YAML has a non-string mapping key")
                if key in result:
                    raise InvalidInput("rendered YAML has duplicate mapping keys")
                result[key] = self.construct_object(value_node, deep=deep)
            return result


def _immutable_image(ref: Any) -> bool:
    if not isinstance(ref, str) or not ref or PLACEHOLDER.search(ref) or ref.count("@") != 1:
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


def _nested(value: Any, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _container_images(pod_spec: Any, identity: tuple[str, str, str, str]) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(pod_spec, dict):
        raise WorkloadMismatch(f"{identity[1]}/{identity[3]} lacks a pod specification")
    primary = pod_spec.get("containers")
    if not isinstance(primary, list) or not primary:
        raise WorkloadMismatch(f"{identity[1]}/{identity[3]} lacks containers")
    result: list[tuple[str, str, str]] = []
    names: set[str] = set()
    for field in ("initContainers", "containers", "ephemeralContainers"):
        entries = pod_spec.get(field, [] if field != "containers" else None)
        if not isinstance(entries, list):
            raise WorkloadMismatch(f"{identity[1]}/{identity[3]} has invalid {field}")
        for entry in entries:
            if not isinstance(entry, dict):
                raise WorkloadMismatch(f"{identity[1]}/{identity[3]} has a non-object container")
            name = entry.get("name")
            image = entry.get("image")
            if (
                not isinstance(name, str)
                or not name
                or name in names
                or not isinstance(image, str)
                or not _immutable_image(image)
            ):
                raise WorkloadMismatch(f"{identity[1]}/{identity[3]} has invalid container identity or image")
            names.add(name)
            result.append((field, name, image))
    return tuple(result)


def _identity(resource: Any, namespace: str, *, live: bool) -> tuple[str, str, str, str]:
    if not isinstance(resource, dict):
        raise InvalidInput("Kubernetes resource is not an object")
    api_version = resource.get("apiVersion")
    kind = resource.get("kind")
    metadata = resource.get("metadata")
    if not isinstance(api_version, str) or not api_version or not isinstance(kind, str) or not kind:
        raise InvalidInput("Kubernetes resource lacks apiVersion or kind")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str) or not metadata["name"]:
        raise InvalidInput("Kubernetes resource lacks metadata.name")
    actual_namespace = metadata.get("namespace")
    if live:
        if actual_namespace != namespace:
            raise WorkloadMismatch("live workload is outside the approved namespace")
    elif (api_version, kind) in POD_PATHS and actual_namespace not in (None, namespace):
        raise WorkloadMismatch("rendered workload is outside the approved namespace")
    return api_version, kind, namespace if actual_namespace is None else actual_namespace, metadata["name"]


def _rendered_documents(raw: str) -> list[Any]:
    if yaml is None:
        raise InvalidInput("PyYAML is required in the controller execution environment")
    if not raw or len(raw.encode("utf-8")) > MAX_RENDERED_BYTES:
        raise InvalidInput("rendered Kubernetes model is empty or exceeds its size limit")
    try:
        documents: list[Any] = []
        for document in yaml.load_all(raw, Loader=_StrictLoader):
            if len(documents) >= MAX_OBJECTS:
                raise InvalidInput("rendered Kubernetes model exceeds its object limit")
            documents.append(document)
    except (yaml.YAMLError, RecursionError) as exc:
        raise InvalidInput("rendered Kubernetes model is invalid or ambiguous YAML") from exc
    if not documents or any(not isinstance(document, dict) for document in documents):
        raise InvalidInput("rendered Kubernetes model must contain nonempty objects")
    return documents


def _workload_map(
    resources: list[Any], namespace: str, *, live: bool
) -> dict[tuple[str, str, str, str], tuple[tuple[str, str, str], ...]]:
    workloads: dict[tuple[str, str, str, str], tuple[tuple[str, str, str], ...]] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for resource in resources:
        identity = _identity(resource, namespace, live=live)
        if identity in seen:
            raise InvalidInput("Kubernetes model contains duplicate resources")
        seen.add(identity)
        path = POD_PATHS.get(identity[:2])
        if path is None:
            if live or _image_key_count(resource):
                raise WorkloadMismatch("Kubernetes model contains an unsupported workload or image field")
            if identity[:2] not in SAFE_NONWORKLOADS:
                raise WorkloadMismatch("rendered Kubernetes model contains an unsupported resource")
            continue
        images = _container_images(_nested(resource, path), identity)
        if _image_key_count(resource) != len(images):
            raise WorkloadMismatch(f"{identity[1]}/{identity[3]} has image fields outside its containers")
        workloads[identity] = images
    if not workloads:
        raise WorkloadMismatch("rendered Kubernetes model contains no supported workloads")
    return workloads


def _job_template_metadata(value: Any, *, job_name: str | None = None, job_uid: str | None = None) -> dict[str, Any]:
    """Remove only labels that the Job controller adds to a pod template."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise WorkloadMismatch("CronJob child has invalid pod template metadata")
    metadata = dict(value)
    labels = metadata.pop("labels", {})
    if not isinstance(labels, dict):
        raise WorkloadMismatch("CronJob child has invalid pod template labels")
    labels = dict(labels)
    if job_name is not None and job_uid is not None:
        for label, field in GENERATED_JOB_LABELS.items():
            if label in labels:
                if labels.pop(label) != (job_uid if field == "uid" else job_name):
                    raise WorkloadMismatch("CronJob child has mismatched Job controller labels")
        if not any(label in value.get("labels", {}) for label in (
            "batch.kubernetes.io/controller-uid", "controller-uid"
        )) or not any(label in value.get("labels", {}) for label in (
            "batch.kubernetes.io/job-name", "job-name"
        )):
            raise WorkloadMismatch("CronJob child lacks Job controller labels")
    if labels:
        metadata["labels"] = labels
    if metadata.get("creationTimestamp") is None:
        metadata.pop("creationTimestamp", None)
    return metadata


def _verify_cronjob_child(
    child: dict[str, Any],
    parent: dict[str, Any],
    namespace: str,
    child_images: tuple[tuple[str, str, str], ...],
    parent_images: tuple[tuple[str, str, str], ...],
) -> None:
    """Allow a generated Job only when it still matches its reviewed CronJob."""
    child_identity = _identity(child, namespace, live=True)
    child_metadata = child["metadata"]
    parent_metadata = parent["metadata"]
    child_uid = child_metadata.get("uid")
    parent_uid = parent_metadata.get("uid")
    references = child_metadata.get("ownerReferences")
    if (
        not isinstance(child_uid, str) or not child_uid
        or not isinstance(parent_uid, str) or not parent_uid
        or not isinstance(references, list) or len(references) != 1
        or not isinstance(references[0], dict)
    ):
        raise WorkloadMismatch("CronJob child lacks a unique controlling owner")
    owner = references[0]
    if (
        owner.get("apiVersion") != "batch/v1"
        or owner.get("kind") != "CronJob"
        or owner.get("name") != parent_metadata.get("name")
        or owner.get("uid") != parent_uid
        or owner.get("controller") is not True
    ):
        raise WorkloadMismatch("CronJob child owner does not match the reviewed live CronJob")
    parent_template = _nested(parent, ("spec", "jobTemplate", "spec", "template"))
    child_template = _nested(child, ("spec", "template"))
    if (
        not isinstance(parent_template, dict)
        or not isinstance(child_template, dict)
        or child_images != parent_images
        or child_template.get("spec") != parent_template.get("spec")
        or _job_template_metadata(child_template.get("metadata"), job_name=child_identity[3], job_uid=child_uid)
        != _job_template_metadata(parent_template.get("metadata"))
    ):
        raise WorkloadMismatch("CronJob child pod template differs from the reviewed CronJob")


def verify(rendered_yaml: str, live_json: Any, namespace: str) -> None:
    """Reject workload drift, except controller-owned Jobs from reviewed CronJobs."""
    if not isinstance(namespace, str) or NAMESPACE.fullmatch(namespace) is None:
        raise InvalidInput("approved namespace is invalid")
    expected = _workload_map(_rendered_documents(rendered_yaml), namespace, live=False)
    if (
        not isinstance(live_json, dict)
        or live_json.get("apiVersion") != "v1"
        or live_json.get("kind") != "List"
        or not isinstance(live_json.get("items"), list)
        or len(live_json["items"]) > MAX_OBJECTS
    ):
        raise InvalidInput("live kubectl result is not a bounded Kubernetes List")
    observed = _workload_map(live_json["items"], namespace, live=True)
    live_resources = {
        _identity(resource, namespace, live=True): resource
        for resource in live_json["items"]
    }
    for identity in observed.keys() - expected.keys():
        if identity[:2] != ("batch/v1", "Job"):
            raise WorkloadMismatch("live namespace has an unreviewed workload")
        child = live_resources[identity]
        references = child["metadata"].get("ownerReferences")
        if not isinstance(references, list) or len(references) != 1 or not isinstance(references[0], dict):
            raise WorkloadMismatch("live namespace has an unreviewed Job")
        owner_name = references[0].get("name")
        if not isinstance(owner_name, str) or not owner_name:
            raise WorkloadMismatch("live Job has an invalid CronJob owner")
        parent_identity = ("batch/v1", "CronJob", namespace, owner_name)
        if parent_identity not in expected or parent_identity not in observed:
            raise WorkloadMismatch("live Job has no reviewed CronJob parent")
        _verify_cronjob_child(
            child, live_resources[parent_identity], namespace, observed[identity], observed[parent_identity]
        )
        del observed[identity]
    if observed != expected:
        raise WorkloadMismatch("live workload identities or container images differ from the reviewed model")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify-live-kubernetes-workloads.py <namespace> < input.json", file=sys.stderr)
        return 2
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES:
        print("live workload input is empty or exceeds its size limit", file=sys.stderr)
        return 2
    try:
        envelope = load_json_document(raw.decode("utf-8", errors="strict"))
        if not isinstance(envelope, dict) or set(envelope) != {"rendered_yaml", "live_json"}:
            raise InvalidInput("live workload envelope has an invalid shape")
        if not isinstance(envelope["rendered_yaml"], str):
            raise InvalidInput("rendered_yaml must be a string")
        verify(envelope["rendered_yaml"], envelope["live_json"], argv[1])
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, WorkloadMismatch):
            print(f"live Kubernetes workload mismatch: {exc}", file=sys.stderr)
            return 1
        print(f"live Kubernetes workload input invalid: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
