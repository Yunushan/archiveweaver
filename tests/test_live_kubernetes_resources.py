from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-live-kubernetes-resources.py"
SPEC = importlib.util.spec_from_file_location("verify_live_kubernetes_resources", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)

NAMESPACE = "archiveweaver"
IMAGE = "registry.example.org/paperless/paperless@sha256:" + "a" * 64
OLD_IMAGE = "registry.example.org/paperless/paperless@sha256:" + "b" * 64
DEPLOY_UID = "11111111-1111-4111-8111-111111111111"
RS_UID = "22222222-2222-4222-8222-222222222222"
POD_UID = "33333333-3333-4333-8333-333333333333"


def resource(version: str, kind: str, name: str, **fields: object) -> dict:
    return {
        "apiVersion": version,
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE},
        **fields,
    }


def owner(parent: dict) -> list[dict]:
    return [{
        "apiVersion": parent["apiVersion"],
        "kind": parent["kind"],
        "name": parent["metadata"]["name"],
        "uid": parent["metadata"]["uid"],
        "controller": True,
    }]


def base() -> tuple[list[dict], list[dict]]:
    namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}}
    service_account = resource("v1", "ServiceAccount", "paperless")
    secret = resource("v1", "Secret", "paperless-secrets-ff9a9d7d5f", type="Opaque")
    service = resource("v1", "Service", "paperless", spec={"ports": [{"port": 8000}]})
    network_policy = resource("networking.k8s.io/v1", "NetworkPolicy", "paperless")
    claim = resource("v1", "PersistentVolumeClaim", "paperless-data")
    pod_spec = {
        "serviceAccountName": "paperless",
        "automountServiceAccountToken": False,
        "containers": [{"name": "paperless", "image": IMAGE}],
    }
    deployment = resource("apps/v1", "Deployment", "paperless", spec={
        "template": {"metadata": {"labels": {"app": "paperless"}}, "spec": pod_spec}
    })
    reviewed = [namespace, service_account, secret, service, network_policy, claim, deployment]
    observed = copy.deepcopy(reviewed[1:])
    observed[-1]["metadata"]["uid"] = DEPLOY_UID
    return reviewed, observed


def model(*resources: dict) -> str:
    return "\n---\n".join(json.dumps(item) for item in resources)


def live_list(*resources: dict) -> dict:
    return {"apiVersion": "v1", "kind": "List", "items": list(resources)}


def generated_replica_set(deployment: dict, *, image: str = IMAGE, replicas: int = 1) -> dict:
    template = copy.deepcopy(deployment["spec"]["template"])
    template["metadata"]["labels"]["pod-template-hash"] = "abcde"
    template["spec"]["containers"][0]["image"] = image
    replica_set = resource("apps/v1", "ReplicaSet", "paperless-abcde", spec={
        "replicas": replicas, "template": template,
    })
    replica_set["metadata"].update({
        "uid": RS_UID,
        "ownerReferences": owner(deployment),
        "labels": {"app": "paperless", "pod-template-hash": "abcde"},
    })
    return replica_set


def generated_pod(parent: dict, *, image: str = IMAGE) -> dict:
    pod_spec = copy.deepcopy(parent["spec"]["template"]["spec"])
    pod_spec["containers"][0]["image"] = image
    pod = resource("v1", "Pod", "paperless-abcde-12345", spec=pod_spec,
                   status={"containerStatuses": [{"name": "paperless", "image": image}]})
    pod["metadata"].update({
        "uid": POD_UID,
        "generateName": parent["metadata"]["name"] + "-",
        "ownerReferences": owner(parent),
    })
    return pod


def cronjob_chain() -> tuple[dict, dict, dict]:
    pod_spec = {
        "serviceAccountName": "paperless",
        "automountServiceAccountToken": False,
        "containers": [{"name": "sweep", "image": IMAGE}],
    }
    cronjob = resource("batch/v1", "CronJob", "sweep", spec={
        "jobTemplate": {"spec": {"template": {
            "metadata": {"labels": {"app": "sweep"}}, "spec": pod_spec,
        }}}
    })
    cronjob["metadata"]["uid"] = "44444444-4444-4444-8444-444444444444"
    job_template = copy.deepcopy(cronjob["spec"]["jobTemplate"]["spec"]["template"])
    job = resource("batch/v1", "Job", "sweep-123456", spec={"template": job_template})
    job["metadata"].update({
        "uid": "55555555-5555-4555-8555-555555555555",
        "ownerReferences": owner(cronjob),
    })
    job_labels = job["spec"]["template"]["metadata"]["labels"]
    job_labels.update({
        "batch.kubernetes.io/controller-uid": job["metadata"]["uid"],
        "batch.kubernetes.io/job-name": job["metadata"]["name"],
    })
    pod = resource("v1", "Pod", "sweep-123456-abcde", spec=copy.deepcopy(pod_spec))
    pod["metadata"].update({
        "uid": "66666666-6666-4666-8666-666666666666",
        "generateName": job["metadata"]["name"] + "-",
        "ownerReferences": owner(job),
    })
    return cronjob, job, pod


class LiveKubernetesResourceTests(unittest.TestCase):
    def test_accepts_exact_inventory_with_generated_secret_replica_set_and_pod(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        pod = generated_pod(replica_set)
        inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_accepts_narrow_default_service_account_and_root_ca_exceptions(self) -> None:
        reviewed, observed = base()
        default_account = resource("v1", "ServiceAccount", "default")
        root_ca = resource("v1", "ConfigMap", "kube-root-ca.crt", data={
            "ca.crt": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
        })
        inventory.verify(model(*reviewed), live_list(*observed, default_account, root_ca), NAMESPACE)

    def test_accepts_generated_cronjob_job_and_pod_with_exact_owner_chain(self) -> None:
        reviewed, observed = base()
        cronjob, job, pod = cronjob_chain()
        reviewed.append(copy.deepcopy(cronjob))
        observed.append(cronjob)
        inventory.verify(model(*reviewed), live_list(*observed, job, pod), NAMESPACE)
        job["metadata"]["ownerReferences"][0]["uid"] = "forged"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, job, pod), NAMESPACE)

    def test_accepts_generated_statefulset_pod_only_with_exact_owner(self) -> None:
        reviewed, observed = base()
        stateful = resource("apps/v1", "StatefulSet", "database", spec={
            "template": {"spec": {
                "serviceAccountName": "paperless",
                "automountServiceAccountToken": False,
                "containers": [{"name": "database", "image": IMAGE}],
            }}
        })
        reviewed.append(copy.deepcopy(stateful))
        stateful["metadata"]["uid"] = "77777777-7777-4777-8777-777777777777"
        observed.append(stateful)
        pod = resource("v1", "Pod", "database-0", spec=copy.deepcopy(stateful["spec"]["template"]["spec"]))
        pod["metadata"].update({
            "uid": "88888888-8888-4888-8888-888888888888",
            "ownerReferences": owner(stateful),
        })
        inventory.verify(model(*reviewed), live_list(*observed, pod), NAMESPACE)
        pod["metadata"]["name"] = "rogue"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, pod), NAMESPACE)

    def test_rejects_extra_authored_resources(self) -> None:
        reviewed, observed = base()
        extras = [
            resource("v1", "Service", "rogue"),
            resource("networking.k8s.io/v1", "NetworkPolicy", "rogue"),
            resource("v1", "Secret", "rogue"),
            resource("v1", "ConfigMap", "rogue"),
            resource("v1", "ServiceAccount", "rogue"),
            resource("v1", "PersistentVolumeClaim", "rogue"),
            resource("v1", "ResourceQuota", "rogue"),
            resource("v1", "LimitRange", "rogue"),
            resource("networking.k8s.io/v1", "Ingress", "rogue"),
            resource("policy/v1", "PodDisruptionBudget", "rogue"),
            resource("autoscaling/v2", "HorizontalPodAutoscaler", "rogue"),
            resource("apps/v1", "Deployment", "rogue"),
            resource("apps/v1", "StatefulSet", "rogue"),
            resource("batch/v1", "Job", "rogue"),
            resource("batch/v1", "CronJob", "rogue"),
            resource("apps/v1", "DaemonSet", "rogue"),
        ]
        for extra in extras:
            with self.subTest(kind=extra["kind"]), self.assertRaises(inventory.InventoryMismatch):
                inventory.verify(model(*reviewed), live_list(*observed, extra), NAMESPACE)

    def test_secret_rotation_fails_closed_until_old_hash_is_retired(self) -> None:
        reviewed, observed = base()
        prior_secret = resource("v1", "Secret", "paperless-secrets-oldhash123", type="Opaque")
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, prior_secret), NAMESPACE)
        inventory.verify(model(*reviewed), live_list(*observed), NAMESPACE)

    def test_rejects_rogue_standalone_pod_with_mutable_image(self) -> None:
        reviewed, observed = base()
        pod = resource("v1", "Pod", "rogue", spec={
            "containers": [{"name": "rogue", "image": "busybox:latest"}]
        })
        pod["metadata"]["uid"] = POD_UID
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, pod), NAMESPACE)

    def test_rejects_forged_owner_and_changed_pod_image(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        replica_set["metadata"]["ownerReferences"][0]["uid"] = "forged"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set), NAMESPACE)
        replica_set = generated_replica_set(observed[-1])
        pod = generated_pod(replica_set, image=OLD_IMAGE)
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_rejects_generated_pod_with_changed_command_or_privileged_mount(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        pod = generated_pod(replica_set)
        pod["spec"]["containers"][0]["command"] = ["sh", "-c", "bad"]
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)
        pod = generated_pod(replica_set)
        pod["spec"]["volumes"] = [{"name": "host", "hostPath": {"path": "/"}}]
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_accepts_narrow_pod_defaults_and_node_placement(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        pod = generated_pod(replica_set)
        pod["spec"].update({
            "nodeName": "worker-1",
            "serviceAccount": "paperless",
            "restartPolicy": "Always",
            "dnsPolicy": "ClusterFirst",
            "schedulerName": "default-scheduler",
            "tolerations": [
                {"key": "node.kubernetes.io/not-ready", "operator": "Exists",
                 "effect": "NoExecute", "tolerationSeconds": 300},
            ],
        })
        pod["spec"]["containers"][0]["terminationMessagePath"] = "/dev/termination-log"
        inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_allows_only_inactive_old_replica_set(self) -> None:
        reviewed, observed = base()
        old = generated_replica_set(observed[-1], image=OLD_IMAGE, replicas=0)
        old["status"] = {"replicas": 0, "readyReplicas": 0, "availableReplicas": 0}
        inventory.verify(model(*reviewed), live_list(*observed, old), NAMESPACE)
        old["spec"]["replicas"] = 1
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, old), NAMESPACE)
        old["spec"]["replicas"] = 0
        old["status"]["readyReplicas"] = 1
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, old), NAMESPACE)

    def test_rejects_pod_from_inactive_old_replica_set(self) -> None:
        reviewed, observed = base()
        old = generated_replica_set(observed[-1], image=OLD_IMAGE, replicas=0)
        pod = generated_pod(old, image=OLD_IMAGE)
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, old, pod), NAMESPACE)

    def test_rejects_system_exception_with_reviewed_default_account_usage(self) -> None:
        reviewed, observed = base()
        reviewed[-1]["spec"]["template"]["spec"]["serviceAccountName"] = "default"
        default_account = resource("v1", "ServiceAccount", "default")
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, default_account), NAMESPACE)

    def test_rejects_unreviewed_system_object_mutations(self) -> None:
        reviewed, observed = base()
        default_account = resource("v1", "ServiceAccount", "default", imagePullSecrets=[{"name": "evil"}])
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, default_account), NAMESPACE)
        root_ca = resource("v1", "ConfigMap", "kube-root-ca.crt", data={"evil": "x"})
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, root_ca), NAMESPACE)
        root_ca["data"] = {"ca.crt": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"}
        root_ca["metadata"]["annotations"] = {"attacker.example/role": "trusted"}
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, root_ca), NAMESPACE)

    def test_rejects_missing_resource_and_wrong_namespace(self) -> None:
        reviewed, observed = base()
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed[:-2]), NAMESPACE)
        observed[0]["metadata"]["namespace"] = "other"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed), NAMESPACE)

    def test_rejects_missing_or_extra_namespace_and_duplicate_resources(self) -> None:
        reviewed, observed = base()
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed[1:]), live_list(*observed), NAMESPACE)
        duplicate_ns = copy.deepcopy(reviewed[0])
        with self.assertRaises(inventory.InvalidInput):
            inventory.verify(model(*reviewed, duplicate_ns), live_list(*observed), NAMESPACE)
        with self.assertRaises(inventory.InvalidInput):
            inventory.verify(model(*reviewed), live_list(*observed, observed[0]), NAMESPACE)

    def test_cli_rejects_ambiguous_json(self) -> None:
        raw = b'{"rendered_yaml":"x","rendered_yaml":"y","live_json":{}}'
        stream = type("Input", (), {"buffer": io.BytesIO(raw)})()
        with patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(inventory.main(["verify-live-kubernetes-resources.py", NAMESPACE]), 2)

    def test_cli_uses_distinct_success_and_drift_exit_codes(self) -> None:
        reviewed, observed = base()
        for resources, expected_exit in ((observed, 0), (observed[:-1], 1)):
            envelope = {"rendered_yaml": model(*reviewed), "live_json": live_list(*resources)}
            stream = type("Input", (), {"buffer": io.BytesIO(json.dumps(envelope).encode())})()
            with patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(inventory.main(["verify-live-kubernetes-resources.py", NAMESPACE]),
                                 expected_exit)


if __name__ == "__main__":
    unittest.main()
