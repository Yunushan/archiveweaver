#!/usr/bin/env python3
"""Reject unreviewed resources in a bounded namespaced Kubernetes inventory.

Usage: verify-live-kubernetes-resources.py <namespace> < input.json
Stdin: {"rendered_yaml": "...", "live_json": <kubectl get ... -o json List>}

The Paperless-ngx/RKE2 caller must obtain one complete List for
INVENTORY_RESOURCES in the approved namespace. This checks authored identities
and narrowly admitted controller descendants. It does not inventory CRDs or
generated EndpointSlices/Endpoints. The caller must also run the separate
reviewed-spec diff, workload verifier, and Namespace UID check.

Pod admission changes beyond the explicit defaults below fail closed. A site
using injected sidecars, tokens, or extra volumes must review and model them
before this gate can certify the deployment.

Kustomize Secret rotation also fails closed: applying a new hashed Secret does
not remove its old name. Final inventory remains mismatched until a separate,
reviewed cleanup has safely retired the old Secret.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from archiveweaver.json_utils import load_json_document  # noqa: E402


def _workload_module() -> ModuleType:
    path = Path(__file__).with_name("verify-live-kubernetes-workloads.py")
    spec = importlib.util.spec_from_file_location("archiveweaver_live_kubernetes_workloads", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("the live workload verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


workloads = _workload_module()

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OBJECTS = 1000
INVENTORY_RESOURCES = (
    "deployments,statefulsets,daemonsets,jobs,cronjobs,pods,replicasets,"
    "services,ingresses,networkpolicies,persistentvolumeclaims,secrets,"
    "configmaps,serviceaccounts,resourcequotas,limitranges,"
    "poddisruptionbudgets,horizontalpodautoscalers,"
    "roles,rolebindings"
)
AUTHORED_KINDS = {
    ("apps/v1", "Deployment"),
    ("apps/v1", "StatefulSet"),
    ("batch/v1", "Job"),
    ("batch/v1", "CronJob"),
    ("v1", "Service"),
    ("v1", "ServiceAccount"),
    ("v1", "ConfigMap"),
    ("v1", "Secret"),
    ("v1", "PersistentVolumeClaim"),
    ("v1", "ResourceQuota"),
    ("v1", "LimitRange"),
    ("networking.k8s.io/v1", "Ingress"),
    ("networking.k8s.io/v1", "NetworkPolicy"),
    ("policy/v1", "PodDisruptionBudget"),
    ("autoscaling/v2", "HorizontalPodAutoscaler"),
    ("rbac.authorization.k8s.io/v1", "Role"),
    ("rbac.authorization.k8s.io/v1", "RoleBinding"),
}
GENERATED_KINDS = {
    ("apps/v1", "ReplicaSet"),
    ("v1", "Pod"),
}
REJECTED_CONTROLLER = ("apps/v1", "DaemonSet")
Identity = tuple[str, str, str, str]


class InvalidInput(ValueError):
    """The invocation or input is malformed (exit 2)."""


class InventoryMismatch(ValueError):
    """The live inventory differs from the reviewed model (exit 1)."""


def _identity(resource: Any, namespace: str, *, live: bool) -> Identity:
    if not isinstance(resource, dict):
        raise InvalidInput("Kubernetes resource is not an object")
    api_version = resource.get("apiVersion")
    kind = resource.get("kind")
    metadata = resource.get("metadata")
    if not isinstance(api_version, str) or not isinstance(kind, str) or not isinstance(metadata, dict):
        raise InvalidInput("Kubernetes resource lacks apiVersion, kind, or metadata")
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise InvalidInput("Kubernetes resource lacks metadata.name")
    if (api_version, kind) == ("v1", "Namespace"):
        if live or name != namespace or metadata.get("namespace") is not None:
            raise InventoryMismatch("rendered Namespace is not the approved namespace")
        return api_version, kind, "", name
    if metadata.get("namespace") != namespace:
        raise InventoryMismatch("namespaced resource is outside the approved namespace")
    return api_version, kind, namespace, name


def _model(rendered_yaml: str, namespace: str) -> dict[Identity, dict[str, Any]]:
    try:
        documents = workloads._rendered_documents(rendered_yaml)
        workloads._workload_map(documents, namespace, live=False)
    except workloads.InvalidInput as exc:
        raise InvalidInput(str(exc)) from exc
    except workloads.WorkloadMismatch as exc:
        raise InventoryMismatch(str(exc)) from exc
    model: dict[Identity, dict[str, Any]] = {}
    namespaces = 0
    for resource in documents:
        identity = _identity(resource, namespace, live=False)
        if identity in model:
            raise InvalidInput("rendered model contains duplicate resources")
        if identity[:2] == ("v1", "Namespace"):
            namespaces += 1
        elif identity[:2] not in AUTHORED_KINDS:
            raise InventoryMismatch("rendered model contains an unsupported namespaced resource")
        model[identity] = resource
    if namespaces != 1:
        raise InventoryMismatch("rendered model must contain one approved Namespace")
    return model


def _observed(live_json: Any, namespace: str) -> dict[Identity, dict[str, Any]]:
    if (
        not isinstance(live_json, dict)
        or live_json.get("apiVersion") != "v1"
        or live_json.get("kind") != "List"
        or not isinstance(live_json.get("items"), list)
        or len(live_json["items"]) > MAX_OBJECTS
    ):
        raise InvalidInput("live result is not a bounded Kubernetes List")
    observed: dict[Identity, dict[str, Any]] = {}
    for resource in live_json["items"]:
        identity = _identity(resource, namespace, live=True)
        if identity in observed:
            raise InvalidInput("live inventory contains duplicate resources")
        if identity[:2] not in AUTHORED_KINDS | GENERATED_KINDS | {REJECTED_CONTROLLER}:
            raise InventoryMismatch("live inventory contains an unsupported resource")
        observed[identity] = resource
    return observed


def _images(resource: dict[str, Any], identity: Identity, path: tuple[str, ...]) -> tuple[Any, ...]:
    try:
        pod_spec = workloads._nested(resource, path)
        images = workloads._container_images(pod_spec, identity)
        if workloads._image_key_count(pod_spec) != len(images):
            raise InventoryMismatch("generated workload has image fields outside containers")
        return cast(tuple[Any, ...], images)
    except workloads.WorkloadMismatch as exc:
        raise InventoryMismatch(str(exc)) from exc


def _owned_by(child: dict[str, Any], parent: dict[str, Any], parent_identity: Identity) -> None:
    metadata = child["metadata"]
    parent_metadata = parent["metadata"]
    references = metadata.get("ownerReferences")
    if (
        not isinstance(metadata.get("uid"), str)
        or not metadata["uid"]
        or not isinstance(parent_metadata.get("uid"), str)
        or not parent_metadata["uid"]
        or not isinstance(references, list)
        or len(references) != 1
        or not isinstance(references[0], dict)
    ):
        raise InventoryMismatch("generated resource lacks a unique controlling owner")
    owner = references[0]
    if (
        owner.get("apiVersion") != parent_identity[0]
        or owner.get("kind") != parent_identity[1]
        or owner.get("name") != parent_identity[3]
        or owner.get("uid") != parent_metadata["uid"]
        or owner.get("controller") is not True
    ):
        raise InventoryMismatch("generated resource owner does not match the live reviewed parent")


def _parent_for(
    child: dict[str, Any], observed: dict[Identity, dict[str, Any]], namespace: str,
    allowed: set[tuple[str, str]],
) -> tuple[Identity, dict[str, Any]]:
    references = child["metadata"].get("ownerReferences")
    if not isinstance(references, list) or len(references) != 1 or not isinstance(references[0], dict):
        raise InventoryMismatch("generated resource has no unique owner")
    owner = references[0]
    key = (owner.get("apiVersion"), owner.get("kind"))
    name = owner.get("name")
    if (
        not isinstance(key[0], str)
        or not isinstance(key[1], str)
        or key not in allowed
        or not isinstance(name, str)
        or not name
    ):
        raise InventoryMismatch("generated resource has an unsupported owner")
    identity = key[0], key[1], namespace, name
    parent = observed.get(identity)
    if parent is None:
        raise InventoryMismatch("generated resource has no reviewed live parent")
    _owned_by(child, parent, identity)
    return identity, parent


def _zero_replicas(replica_set: dict[str, Any]) -> bool:
    spec = replica_set.get("spec")
    status = replica_set.get("status", {})
    if (
        not isinstance(spec, dict)
        or not isinstance(status, dict)
        or type(spec.get("replicas")) is not int
        or spec["replicas"] != 0
    ):
        return False
    return all(type(status.get(field, 0)) is int and status.get(field, 0) == 0 for field in (
        "replicas", "readyReplicas", "availableReplicas", "fullyLabeledReplicas"
    ))


def _replica_set_current(replica_set: dict[str, Any], deployment: dict[str, Any], identity: Identity) -> bool:
    child_template = workloads._nested(replica_set, ("spec", "template"))
    parent_template = workloads._nested(deployment, ("spec", "template"))
    if not isinstance(child_template, dict) or not isinstance(parent_template, dict):
        raise InventoryMismatch("ReplicaSet lacks a pod template")
    child_metadata = child_template.get("metadata", {})
    parent_metadata = parent_template.get("metadata", {})
    if not isinstance(child_metadata, dict) or not isinstance(parent_metadata, dict):
        raise InventoryMismatch("ReplicaSet has invalid template metadata")
    child_labels = child_metadata.get("labels", {})
    parent_labels = parent_metadata.get("labels", {})
    if not isinstance(child_labels, dict) or not isinstance(parent_labels, dict):
        raise InventoryMismatch("ReplicaSet has invalid template labels")
    hash_label = child_labels.get("pod-template-hash")
    if not isinstance(hash_label, str) or not hash_label:
        raise InventoryMismatch("ReplicaSet lacks its controller hash label")
    if identity[3] != deployment["metadata"]["name"] + "-" + hash_label:
        raise InventoryMismatch("ReplicaSet name does not match its controller hash")
    rs_labels = replica_set["metadata"].get("labels", {})
    if not isinstance(rs_labels, dict) or rs_labels.get("pod-template-hash") != hash_label:
        raise InventoryMismatch("ReplicaSet controller hash labels differ")
    normalized_metadata = dict(child_metadata)
    normalized_metadata["labels"] = {k: v for k, v in child_labels.items() if k != "pod-template-hash"}
    return (
        normalized_metadata == parent_metadata
        and child_template.get("spec") == parent_template.get("spec")
        and _images(replica_set, identity, ("spec", "template", "spec"))
        == _images(deployment, ("apps/v1", "Deployment", identity[2], deployment["metadata"]["name"]),
                   ("spec", "template", "spec"))
    )


def _reviewed_pods_isolated(model: dict[Identity, dict[str, Any]]) -> bool:
    for identity, resource in model.items():
        path = workloads.POD_PATHS.get(identity[:2])
        if path is None:
            continue
        pod_spec = workloads._nested(resource, path)
        if not isinstance(pod_spec, dict):
            return False
        account = pod_spec.get("serviceAccountName")
        if not isinstance(account, str) or not account or account == "default":
            return False
        if pod_spec.get("automountServiceAccountToken") is not False:
            return False
        volumes = pod_spec.get("volumes", [])
        if not isinstance(volumes, list):
            return False
        if any(
            isinstance(volume, dict)
            and isinstance(volume.get("configMap"), dict)
            and volume["configMap"].get("name") == "kube-root-ca.crt"
            for volume in volumes
        ):
            return False
    return True


def _pod_matches_template(pod: dict[str, Any], parent: dict[str, Any]) -> bool:
    """Admit only ordinary API defaults and scheduling fields on a child Pod."""
    parent_template = workloads._nested(parent, ("spec", "template"))
    if not isinstance(parent_template, dict):
        return False
    template_spec = parent_template.get("spec")
    pod_spec = pod.get("spec")
    if not isinstance(template_spec, dict) or not isinstance(pod_spec, dict):
        return False
    expected = copy.deepcopy(template_spec)
    actual = copy.deepcopy(pod_spec)
    node_name = actual.pop("nodeName", None)
    if node_name is not None and (not isinstance(node_name, str) or not node_name):
        return False
    service_account_alias = actual.pop("serviceAccount", None)
    if service_account_alias is not None and service_account_alias != actual.get("serviceAccountName"):
        return False
    defaults: dict[str, Any] = {
        "restartPolicy": "Always",
        "dnsPolicy": "ClusterFirst",
        "schedulerName": "default-scheduler",
        "terminationGracePeriodSeconds": 30,
        "enableServiceLinks": True,
        "priority": 0,
        "preemptionPolicy": "PreemptLowerPriority",
        "securityContext": {},
        "imagePullSecrets": [],
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        "shareProcessNamespace": False,
    }
    for field, default in defaults.items():
        if field not in expected and actual.get(field) == default:
            actual.pop(field, None)
    default_tolerations = [
        {"key": f"node.kubernetes.io/{reason}", "operator": "Exists", "effect": "NoExecute",
         "tolerationSeconds": 300}
        for reason in ("not-ready", "unreachable")
    ]
    if "tolerations" not in expected and isinstance(actual.get("tolerations"), list):
        extras = actual["tolerations"]
        if all(toleration in default_tolerations for toleration in extras):
            actual.pop("tolerations")
    container_defaults: dict[str, Any] = {
        "imagePullPolicy": "IfNotPresent",
        "terminationMessagePath": "/dev/termination-log",
        "terminationMessagePolicy": "File",
        "stdin": False,
        "tty": False,
        "resources": {},
        "securityContext": {},
    }
    for field in ("initContainers", "containers", "ephemeralContainers"):
        expected_containers = expected.get(field, [])
        actual_containers = actual.get(field, [])
        if not isinstance(expected_containers, list) or not isinstance(actual_containers, list):
            return False
        if len(expected_containers) != len(actual_containers):
            return False
        for expected_container, actual_container in zip(expected_containers, actual_containers):
            if not isinstance(expected_container, dict) or not isinstance(actual_container, dict):
                return False
            for key, default in container_defaults.items():
                if key not in expected_container and actual_container.get(key) == default:
                    actual_container.pop(key, None)
    return actual == expected


def _system_exception(
    identity: Identity, resource: dict[str, Any], model: dict[Identity, dict[str, Any]]
) -> bool:
    if not _reviewed_pods_isolated(model):
        return False
    metadata = resource["metadata"]
    if metadata.get("ownerReferences"):
        return False
    labels = metadata.get("labels", {})
    if (
        not isinstance(labels, dict)
        or set(labels) - {"kubernetes.io/metadata.name"}
        or labels.get("kubernetes.io/metadata.name", identity[3]) != identity[3]
    ):
        return False
    if identity[:2] == ("v1", "ServiceAccount") and identity[3] == "default":
        return (
            resource.get("secrets") in (None, [])
            and resource.get("imagePullSecrets") in (None, [])
            and not metadata.get("annotations")
            and (
                resource.get("automountServiceAccountToken") is None
                or resource.get("automountServiceAccountToken") is False
            )
        )
    if identity[:2] == ("v1", "ConfigMap") and identity[3] == "kube-root-ca.crt":
        data = resource.get("data")
        certificate = data.get("ca.crt") if isinstance(data, dict) and set(data) == {"ca.crt"} else None
        annotations = metadata.get("annotations", {})
        return (
            isinstance(certificate, str)
            and certificate.startswith("-----BEGIN CERTIFICATE-----\n")
            and "-----END CERTIFICATE-----" in certificate
            and not resource.get("binaryData")
            and (resource.get("immutable") is None or resource.get("immutable") is False)
            and isinstance(annotations, dict)
            and set(annotations) <= {"kubernetes.io/description"}
        )
    return False


def verify(rendered_yaml: str, live_json: Any, namespace: str) -> None:
    """Compare a complete fixed-kind inventory with reviewed names and owners."""
    if not isinstance(namespace, str) or workloads.NAMESPACE.fullmatch(namespace) is None:
        raise InvalidInput("approved namespace is invalid")
    model = _model(rendered_yaml, namespace)
    observed = _observed(live_json, namespace)
    authored = {identity for identity in model if identity[:2] != ("v1", "Namespace")}
    missing = authored - observed.keys()
    if missing:
        raise InventoryMismatch("reviewed namespaced resource is missing from the live inventory")
    for identity in observed.keys() & authored:
        if identity[:2] in workloads.POD_PATHS:
            _images(observed[identity], identity, workloads.POD_PATHS[identity[:2]])

    admitted: set[Identity] = set(authored)
    stale_replicas: set[Identity] = set()
    for identity, resource in observed.items():
        if identity[:2] != ("apps/v1", "ReplicaSet"):
            continue
        parent_identity, parent = _parent_for(resource, observed, namespace, {("apps/v1", "Deployment")})
        if parent_identity not in authored or not identity[3].startswith(parent_identity[3] + "-"):
            raise InventoryMismatch("ReplicaSet is not a generated descendant of a reviewed Deployment")
        if not _replica_set_current(resource, parent, identity):
            if not _zero_replicas(resource):
                raise InventoryMismatch("active ReplicaSet differs from the reviewed Deployment")
            stale_replicas.add(identity)
        admitted.add(identity)

    for identity, resource in observed.items():
        if identity[:2] != ("batch/v1", "Job") or identity in authored:
            continue
        parent_identity, parent = _parent_for(resource, observed, namespace, {("batch/v1", "CronJob")})
        if parent_identity not in authored or not identity[3].startswith(parent_identity[3] + "-"):
            raise InventoryMismatch("Job has no reviewed CronJob owner")
        try:
            workloads._verify_cronjob_child(
                resource, parent, namespace,
                _images(resource, identity, ("spec", "template", "spec")),
                _images(parent, parent_identity, ("spec", "jobTemplate", "spec", "template", "spec")),
            )
        except workloads.WorkloadMismatch as exc:
            raise InventoryMismatch(str(exc)) from exc
        admitted.add(identity)

    for identity, resource in observed.items():
        if identity[:2] != ("v1", "Pod"):
            continue
        parent_identity, parent = _parent_for(
            resource, observed, namespace,
            {("apps/v1", "ReplicaSet"), ("apps/v1", "StatefulSet"), ("batch/v1", "Job")},
        )
        if parent_identity not in admitted or parent_identity in stale_replicas:
            raise InventoryMismatch("Pod is not a current descendant of a reviewed controller")
        if parent_identity[:2] in {("apps/v1", "ReplicaSet"), ("batch/v1", "Job")}:
            if (
                not identity[3].startswith(parent_identity[3] + "-")
                or resource["metadata"].get("generateName") != parent_identity[3] + "-"
            ):
                raise InventoryMismatch("generated Pod name does not match its controller")
        if parent_identity[:2] == ("apps/v1", "ReplicaSet"):
            path = ("spec", "template", "spec")
        elif parent_identity[:2] == ("apps/v1", "StatefulSet"):
            path = ("spec", "template", "spec")
            suffix = identity[3].removeprefix(parent_identity[3] + "-")
            if not suffix.isdecimal() or identity[3] != parent_identity[3] + "-" + suffix:
                raise InventoryMismatch("StatefulSet Pod name does not match its owner")
        else:
            path = ("spec", "template", "spec")
        if _images(resource, identity, ("spec",)) != _images(parent, parent_identity, path):
            raise InventoryMismatch("generated Pod image set differs from its reviewed controller")
        if not _pod_matches_template(resource, parent):
            raise InventoryMismatch("generated Pod specification differs from its reviewed controller")
        admitted.add(identity)

    for identity, resource in observed.items():
        if identity in admitted or _system_exception(identity, resource, model):
            continue
        raise InventoryMismatch("live namespace contains an unreviewed resource")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify-live-kubernetes-resources.py <namespace> < input.json", file=sys.stderr)
        return 2
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES:
        print("live resource input is empty or exceeds its size limit", file=sys.stderr)
        return 2
    try:
        envelope = load_json_document(raw.decode("utf-8", errors="strict"))
        if not isinstance(envelope, dict) or set(envelope) != {"rendered_yaml", "live_json"}:
            raise InvalidInput("live resource envelope has an invalid shape")
        if not isinstance(envelope["rendered_yaml"], str):
            raise InvalidInput("rendered_yaml must be a string")
        verify(envelope["rendered_yaml"], envelope["live_json"], argv[1])
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, InventoryMismatch):
            print(f"live Kubernetes resource mismatch: {exc}", file=sys.stderr)
            return 1
        print(f"live Kubernetes resource input invalid: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
