from __future__ import annotations

import copy
import importlib.util
import io
import json
import runpy
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

    def test_workload_verifier_unavailable_when_spec_is_missing(self) -> None:
        spec = importlib.util.spec_from_file_location("verify_live_kubernetes_resources_noloader", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        with patch("importlib.util.spec_from_file_location", return_value=None):
            with self.assertRaises(RuntimeError):
                assert spec is not None and spec.loader is not None
                spec.loader.exec_module(module)

    def test_rejects_malformed_live_resource_objects(self) -> None:
        reviewed, observed = base()
        for resource in (42, {"apiVersion": "v1", "kind": "Secret"}, {"apiVersion": "v1", "kind": "Secret", "metadata": {}}):
            with self.subTest(resource=resource), self.assertRaises(inventory.InvalidInput):
                inventory.verify(model(*reviewed), live_list(*observed, resource), NAMESPACE)

    def test_rejects_rendered_namespace_that_is_not_approved(self) -> None:
        reviewed, observed = base()
        other_namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other"}}
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(other_namespace, *reviewed[1:]), live_list(*observed), NAMESPACE)

    def test_translates_workload_verifier_mismatch(self) -> None:
        reviewed, observed = base()
        reviewed[-1]["spec"]["template"]["spec"]["image"] = "stray"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed), NAMESPACE)

    def test_model_rejects_duplicate_rendered_resources(self) -> None:
        duplicate = resource("v1", "Secret", "shared")
        with patch.object(inventory.workloads, "_rendered_documents", return_value=[duplicate, copy.deepcopy(duplicate)]), \
                patch.object(inventory.workloads, "_workload_map", return_value={}):
            with self.assertRaises(inventory.InvalidInput):
                inventory._model("ignored", NAMESPACE)

    def test_rejects_rendered_unsupported_namespaced_resource(self) -> None:
        reviewed, observed = base()
        endpoints = resource("v1", "Endpoints", "rogue")
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed, endpoints), live_list(*observed), NAMESPACE)

    def test_rejects_malformed_live_list_and_unsupported_live_resource(self) -> None:
        reviewed, observed = base()
        with self.assertRaises(inventory.InvalidInput):
            inventory.verify(model(*reviewed), "not-a-list", NAMESPACE)
        endpoints = resource("v1", "Endpoints", "rogue")
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, endpoints), NAMESPACE)

    def test_rejects_observed_workload_image_anomalies(self) -> None:
        reviewed, observed = base()
        with_extra_image = copy.deepcopy(observed)
        with_extra_image[-1]["spec"]["template"]["spec"]["image"] = "stray"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*with_extra_image), NAMESPACE)
        without_containers = copy.deepcopy(observed)
        without_containers[-1]["spec"]["template"]["spec"] = {}
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*without_containers), NAMESPACE)

    def test_rejects_replica_set_ownership_anomalies(self) -> None:
        reviewed, observed = base()
        cases = []
        missing_uid = generated_replica_set(observed[-1])
        missing_uid["metadata"].pop("uid")
        cases.append(missing_uid)
        wrong_owner_kind = generated_replica_set(observed[-1])
        wrong_owner_kind["metadata"]["ownerReferences"][0]["kind"] = "DaemonSet"
        cases.append(wrong_owner_kind)
        missing_parent = generated_replica_set(observed[-1])
        missing_parent["metadata"]["ownerReferences"][0]["name"] = "missing"
        cases.append(missing_parent)
        for replica_set in cases:
            with self.subTest(replica_set=replica_set), self.assertRaises(inventory.InventoryMismatch):
                inventory.verify(model(*reviewed), live_list(*observed, replica_set), NAMESPACE)

    def test_rejects_replica_set_template_anomalies(self) -> None:
        reviewed, observed = base()
        cases = []
        bad_template = generated_replica_set(observed[-1])
        bad_template["spec"]["template"] = "not-an-object"
        cases.append(bad_template)
        bad_metadata = generated_replica_set(observed[-1])
        bad_metadata["spec"]["template"] = {"metadata": []}
        cases.append(bad_metadata)
        bad_labels = generated_replica_set(observed[-1])
        bad_labels["spec"]["template"] = {"metadata": {"labels": []}}
        cases.append(bad_labels)
        no_hash = generated_replica_set(observed[-1])
        no_hash["spec"]["template"]["metadata"]["labels"].pop("pod-template-hash")
        cases.append(no_hash)
        name_mismatch = generated_replica_set(observed[-1])
        name_mismatch["spec"]["template"]["metadata"]["labels"]["pod-template-hash"] = "zzzzz"
        cases.append(name_mismatch)
        parent_labels_mismatch = generated_replica_set(observed[-1])
        parent_labels_mismatch["metadata"]["labels"]["pod-template-hash"] = "zzzzz"
        cases.append(parent_labels_mismatch)
        for replica_set in cases:
            with self.subTest(replica_set=replica_set), self.assertRaises(inventory.InventoryMismatch):
                inventory.verify(model(*reviewed), live_list(*observed, replica_set), NAMESPACE)

    def test_rejects_replica_set_and_pod_name_mismatch(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        replica_set["metadata"]["name"] = "other-abcde"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set), NAMESPACE)
        replica_set = generated_replica_set(observed[-1])
        pod = generated_pod(replica_set)
        pod["metadata"]["name"] = "rogue"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_reviewed_pods_isolated_guards(self) -> None:
        identity = ("apps/v1", "Deployment", NAMESPACE, "paperless")
        non_object_spec = {identity: {"spec": {"template": {"spec": "not-an-object"}}}}
        self.assertFalse(inventory._reviewed_pods_isolated(non_object_spec))
        cases = []
        automount_enabled = copy.deepcopy(non_object_spec)
        automount_enabled[identity] = {"spec": {"template": {"spec": {
            "serviceAccountName": "paperless", "automountServiceAccountToken": True,
        }}}}
        cases.append(automount_enabled)
        bad_volumes = copy.deepcopy(automount_enabled)
        bad_volumes[identity]["spec"]["template"]["spec"]["automountServiceAccountToken"] = False
        bad_volumes[identity]["spec"]["template"]["spec"]["volumes"] = "not-a-list"
        cases.append(bad_volumes)
        root_ca_volume = copy.deepcopy(bad_volumes)
        root_ca_volume[identity]["spec"]["template"]["spec"]["volumes"] = [
            {"name": "ca", "configMap": {"name": "kube-root-ca.crt"}}
        ]
        cases.append(root_ca_volume)
        for model_state in cases:
            with self.subTest(model=model_state):
                self.assertFalse(inventory._reviewed_pods_isolated(model_state))

    def test_pod_matches_template_direct_guards(self) -> None:
        self.assertFalse(inventory._pod_matches_template({}, {"spec": {"template": "not-an-object"}}))
        self.assertFalse(inventory._pod_matches_template({}, {"spec": {"template": {"spec": "not-an-object"}}}))
        self.assertFalse(inventory._pod_matches_template(
            {"spec": {}}, {"spec": {"template": {"spec": {"initContainers": "not-a-list"}}}}))
        self.assertFalse(inventory._pod_matches_template(
            {"spec": {"initContainers": [{"name": "a"}, {"name": "b"}]}},
            {"spec": {"template": {"spec": {"initContainers": [{"name": "a"}]}}}}))
        self.assertFalse(inventory._pod_matches_template(
            {"spec": {"initContainers": [1]}},
            {"spec": {"template": {"spec": {"initContainers": [1]}}}}))

    def test_rejects_generated_pod_default_and_placement_anomalies(self) -> None:
        reviewed, observed = base()
        replica_set = generated_replica_set(observed[-1])
        cases = []
        empty_node = generated_pod(replica_set)
        empty_node["spec"]["nodeName"] = ""
        cases.append(empty_node)
        bad_alias = generated_pod(replica_set)
        bad_alias["spec"]["serviceAccount"] = "other"
        cases.append(bad_alias)
        custom_toleration = generated_pod(replica_set)
        custom_toleration["spec"]["tolerations"] = [{"key": "custom"}]
        cases.append(custom_toleration)
        for pod in cases:
            with self.subTest(pod=pod), self.assertRaises(inventory.InventoryMismatch):
                inventory.verify(model(*reviewed), live_list(*observed, replica_set, pod), NAMESPACE)

    def test_rejects_system_exception_owner_and_label_mutations(self) -> None:
        reviewed, observed = base()
        owned = resource("v1", "ServiceAccount", "default")
        owned["metadata"]["ownerReferences"] = [{"kind": "Role"}]
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, owned), NAMESPACE)
        mislabeled = resource("v1", "ServiceAccount", "default")
        mislabeled["metadata"]["labels"] = {"attacker.example/role": "trusted"}
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, mislabeled), NAMESPACE)

    def test_rejects_unreviewed_cronjob_child_template_and_missing_owner(self) -> None:
        reviewed, observed = base()
        cronjob, job, _ = cronjob_chain()
        reviewed.append(copy.deepcopy(cronjob))
        observed.append(cronjob)
        drifted = copy.deepcopy(job)
        drifted["spec"]["template"]["spec"]["containers"][0]["command"] = ["unexpected"]
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, drifted), NAMESPACE)
        orphan_job = copy.deepcopy(job)
        orphan_job["metadata"]["ownerReferences"][0]["name"] = "unreviewed"
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed, orphan_job), NAMESPACE)

    def test_rejects_job_without_reviewed_cronjob_parent(self) -> None:
        reviewed, observed = base()
        cronjob, job, _ = cronjob_chain()
        observed.append(cronjob)
        observed.append(job)
        with self.assertRaises(inventory.InventoryMismatch):
            inventory.verify(model(*reviewed), live_list(*observed), NAMESPACE)

    def test_verify_rejects_invalid_namespace(self) -> None:
        with self.assertRaises(inventory.InvalidInput):
            inventory.verify("x", {}, "Bad_Namespace")

    def test_cli_usage_and_input_guards(self) -> None:
        with patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(inventory.main(["verify-live-kubernetes-resources.py"]), 2)
        empty = type("Input", (), {"buffer": io.BytesIO(b"")})()
        with patch.object(sys, "stdin", empty), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(inventory.main(["verify-live-kubernetes-resources.py", NAMESPACE]), 2)
        oversized = type("Input", (), {"buffer": io.BytesIO(b"x" * 16)})()
        with patch.object(inventory, "MAX_INPUT_BYTES", 4), patch.object(sys, "stdin", oversized), \
                patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(inventory.main(["verify-live-kubernetes-resources.py", NAMESPACE]), 2)

    def test_cli_envelope_shape_and_rendered_type(self) -> None:
        def run(raw: bytes) -> int:
            stream = type("Input", (), {"buffer": io.BytesIO(raw)})()
            with patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
                return inventory.main(["verify-live-kubernetes-resources.py", NAMESPACE])

        self.assertEqual(run(json.dumps({"only": 1}).encode()), 2)
        self.assertEqual(run(json.dumps({"rendered_yaml": 5, "live_json": {}}).encode()), 2)

    def test_main_guard_runs_and_exits(self) -> None:
        stream = type("Input", (), {"buffer": io.BytesIO(b"")})()
        with patch.object(sys, "argv", ["verify-live-kubernetes-resources.py"]), \
                patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
