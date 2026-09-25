from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-live-kubernetes-workloads.py"
SPEC = importlib.util.spec_from_file_location("verify_live_kubernetes_workloads", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
live = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = live
SPEC.loader.exec_module(live)

NAMESPACE = "documents"
IMAGE = "registry.example.org/docs/paperless@sha256:" + "a" * 64
DB_IMAGE = "registry.example.org/database/postgres@sha256:" + "b" * 64
BROKER_IMAGE = "registry.example.org/cache/valkey@sha256:" + "c" * 64
CRONJOB_UID = "11111111-1111-4111-8111-111111111111"
JOB_UID = "22222222-2222-4222-8222-222222222222"


def workload(kind: str, name: str, image: str = IMAGE) -> dict:
    pod_spec = {"containers": [{"name": name, "image": image}]}
    if kind == "CronJob":
        spec = {"jobTemplate": {"spec": {"template": {"spec": pod_spec}}}}
        version = "batch/v1"
    elif kind == "Job":
        spec = {"template": {"spec": pod_spec}}
        version = "batch/v1"
    else:
        spec = {"template": {"spec": pod_spec}}
        version = "apps/v1"
    return {
        "apiVersion": version,
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": spec,
    }


def model(*resources: dict) -> str:
    return "\n---\n".join(json.dumps(resource) for resource in resources)


def live_list(*resources: dict) -> dict:
    return {"apiVersion": "v1", "kind": "List", "items": list(resources)}


def generated_job(parent: dict, name: str = "consume-123") -> dict:
    parent_uid = parent["metadata"]["uid"]
    template = copy.deepcopy(parent["spec"]["jobTemplate"]["spec"]["template"])
    metadata = template.setdefault("metadata", {})
    metadata["labels"] = {
        **metadata.get("labels", {}),
        "batch.kubernetes.io/controller-uid": JOB_UID,
        "batch.kubernetes.io/job-name": name,
        "controller-uid": JOB_UID,
        "job-name": name,
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "uid": JOB_UID,
            "ownerReferences": [{
                "apiVersion": "batch/v1",
                "kind": "CronJob",
                "name": parent["metadata"]["name"],
                "uid": parent_uid,
                "controller": True,
            }],
        },
        "spec": {"template": template},
    }


class LiveKubernetesWorkloadTests(unittest.TestCase):
    def test_exact_full_workload_set_and_every_container_class_passes(self) -> None:
        deployment = workload("Deployment", "paperless")
        pod = deployment["spec"]["template"]["spec"]
        pod["initContainers"] = [{"name": "migrate", "image": DB_IMAGE}]
        pod["ephemeralContainers"] = [{"name": "diagnostic", "image": BROKER_IMAGE}]
        resources = [
            deployment,
            workload("StatefulSet", "database", DB_IMAGE),
            workload("Job", "setup", IMAGE),
            workload("CronJob", "consume", BROKER_IMAGE),
        ]
        namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}}
        live.verify(model(namespace, *resources), live_list(*copy.deepcopy(resources)), NAMESPACE)

    def test_rejects_missing_or_extra_workload(self) -> None:
        deployment = workload("Deployment", "paperless")
        database = workload("StatefulSet", "database", DB_IMAGE)
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment, database), live_list(deployment), NAMESPACE)
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment), live_list(deployment, database), NAMESPACE)

    def test_accepts_only_matching_jobs_created_by_a_reviewed_cronjob(self) -> None:
        deployment = workload("Deployment", "paperless")
        reviewed_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        reviewed_cronjob["spec"]["jobTemplate"]["spec"]["template"]["metadata"] = {
            "labels": {"app": "consume"}, "annotations": {"policy": "reviewed"}
        }
        live_cronjob = copy.deepcopy(reviewed_cronjob)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        live.verify(
            model(deployment, reviewed_cronjob),
            live_list(deployment, live_cronjob, child),
            NAMESPACE,
        )

    def test_rejects_unowned_or_unreviewed_cronjob_children(self) -> None:
        deployment = workload("Deployment", "paperless")
        reviewed_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        live_cronjob = copy.deepcopy(reviewed_cronjob)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        changed_children = []
        orphan = copy.deepcopy(child)
        orphan["metadata"].pop("ownerReferences")
        changed_children.append(orphan)
        wrong_uid = copy.deepcopy(child)
        wrong_uid["metadata"]["ownerReferences"][0]["uid"] = JOB_UID
        changed_children.append(wrong_uid)
        wrong_parent = copy.deepcopy(child)
        wrong_parent["metadata"]["ownerReferences"][0]["name"] = "unreviewed"
        changed_children.append(wrong_parent)
        not_controller = copy.deepcopy(child)
        not_controller["metadata"]["ownerReferences"][0]["controller"] = False
        changed_children.append(not_controller)
        duplicate_owner = copy.deepcopy(child)
        duplicate_owner["metadata"]["ownerReferences"].append(
            copy.deepcopy(duplicate_owner["metadata"]["ownerReferences"][0])
        )
        changed_children.append(duplicate_owner)
        for changed in changed_children:
            with self.subTest(child=changed), self.assertRaises(live.WorkloadMismatch):
                live.verify(
                    model(deployment, reviewed_cronjob),
                    live_list(deployment, live_cronjob, changed),
                    NAMESPACE,
                )
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment), live_list(deployment, child), NAMESPACE)

    def test_rejects_cronjob_child_image_or_template_drift(self) -> None:
        deployment = workload("Deployment", "paperless")
        reviewed_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        live_cronjob = copy.deepcopy(reviewed_cronjob)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        changed_children = []
        changed_image = copy.deepcopy(child)
        changed_image["spec"]["template"]["spec"]["containers"][0]["image"] = IMAGE
        changed_children.append(changed_image)
        changed_command = copy.deepcopy(child)
        changed_command["spec"]["template"]["spec"]["containers"][0]["command"] = ["unexpected"]
        changed_children.append(changed_command)
        changed_annotation = copy.deepcopy(child)
        changed_annotation["spec"]["template"]["metadata"]["annotations"] = {"unexpected": "true"}
        changed_children.append(changed_annotation)
        wrong_label = copy.deepcopy(child)
        wrong_label["spec"]["template"]["metadata"]["labels"]["batch.kubernetes.io/controller-uid"] = CRONJOB_UID
        changed_children.append(wrong_label)
        missing_labels = copy.deepcopy(child)
        missing_labels["spec"]["template"]["metadata"].pop("labels")
        changed_children.append(missing_labels)
        for changed in changed_children:
            with self.subTest(child=changed), self.assertRaises(live.WorkloadMismatch):
                live.verify(
                    model(deployment, reviewed_cronjob),
                    live_list(deployment, live_cronjob, changed),
                    NAMESPACE,
                )

    def test_rejects_changed_regular_init_or_ephemeral_image(self) -> None:
        expected = workload("Deployment", "paperless")
        pod = expected["spec"]["template"]["spec"]
        pod["initContainers"] = [{"name": "migrate", "image": DB_IMAGE}]
        pod["ephemeralContainers"] = [{"name": "diagnostic", "image": BROKER_IMAGE}]
        for field in ("containers", "initContainers", "ephemeralContainers"):
            observed = copy.deepcopy(expected)
            observed["spec"]["template"]["spec"][field][0]["image"] = IMAGE if field != "containers" else DB_IMAGE
            with self.subTest(field=field), self.assertRaises(live.WorkloadMismatch):
                live.verify(model(expected), live_list(observed), NAMESPACE)

    def test_rejects_changed_container_name_and_duplicate_name(self) -> None:
        expected = workload("Deployment", "paperless")
        observed = copy.deepcopy(expected)
        observed["spec"]["template"]["spec"]["containers"][0]["name"] = "other"
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected), live_list(observed), NAMESPACE)
        observed = copy.deepcopy(expected)
        observed["spec"]["template"]["spec"]["initContainers"] = [{"name": "paperless", "image": DB_IMAGE}]
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected), live_list(observed), NAMESPACE)

    def test_rejects_live_workload_in_other_namespace(self) -> None:
        expected = workload("Deployment", "paperless")
        observed = copy.deepcopy(expected)
        observed["metadata"]["namespace"] = "other"
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected), live_list(observed), NAMESPACE)

    def test_rejects_rendered_unsupported_image_workload(self) -> None:
        expected = workload("Deployment", "paperless")
        daemon = workload("DaemonSet", "hidden")
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected, daemon), live_list(expected), NAMESPACE)

    def test_rejects_mutable_or_ambiguous_registry_references(self) -> None:
        invalid_images = (
            "paperless:latest",
            "paperless@sha256:" + "a" * 64,
            "registry.example.org:99999/docs/paperless@sha256:" + "a" * 64,
            "registry.example.org/docs/paperless___bad@sha256:" + "a" * 64,
        )
        for image in invalid_images:
            expected = workload("Deployment", "paperless", image)
            with self.subTest(image=image), self.assertRaises(live.WorkloadMismatch):
                live.verify(model(expected), live_list(expected), NAMESPACE)

    def test_rejects_unrecognized_rendered_resource_even_without_image(self) -> None:
        expected = workload("Deployment", "paperless")
        custom = {"apiVersion": "example.org/v1", "kind": "Controller", "metadata": {"name": "hidden"}}
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected, custom), live_list(expected), NAMESPACE)

    def test_rejects_duplicate_rendered_yaml_keys(self) -> None:
        expected = workload("Deployment", "paperless")
        duplicate = model(expected).replace('"kind": "Deployment",', '"kind": "Deployment", "kind": "Job",')
        with self.assertRaises(live.InvalidInput):
            live.verify(duplicate, live_list(expected), NAMESPACE)

    def test_rejects_malformed_live_list_and_duplicate_resources(self) -> None:
        expected = workload("Deployment", "paperless")
        with self.assertRaises(live.InvalidInput):
            live.verify(model(expected), {"kind": "List", "items": [expected]}, NAMESPACE)
        with self.assertRaises(live.InvalidInput):
            live.verify(model(expected), live_list(expected, expected), NAMESPACE)

    def test_cli_rejects_duplicate_json_envelope_keys(self) -> None:
        envelope = b'{"rendered_yaml":"x","rendered_yaml":"y","live_json":{}}'
        stream = type("Input", (), {"buffer": io.BytesIO(envelope)})()
        with patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(live.main(["verify-live-kubernetes-workloads.py", NAMESPACE]), 2)


if __name__ == "__main__":
    unittest.main()
