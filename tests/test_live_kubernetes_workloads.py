from __future__ import annotations

import builtins
import copy
import importlib.util
import io
import json
import runpy
import sys
import unittest
import yaml
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

    def test_module_without_pyyaml_fails_deterministically(self) -> None:
        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "yaml":
                raise ImportError("PyYAML is not installed")
            return real_import(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("verify_live_kubernetes_workloads_noyaml", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        with patch.object(builtins, "__import__", fake_import):
            assert spec is not None and spec.loader is not None
            spec.loader.exec_module(module)
        self.assertIsNone(module.yaml)
        self.assertFalse(hasattr(module, "_StrictLoader"))
        with self.assertRaises(module.InvalidInput):
            module._rendered_documents("{}")

    def test_strict_loader_rejects_non_mapping_node(self) -> None:
        loader = live._StrictLoader("a: 1")
        node = yaml.ScalarNode("tag:yaml.org,2002:str", "scalar")
        with self.assertRaises(live.InvalidInput):
            loader.construct_mapping(node)

    def test_rejects_yaml_alias_and_non_string_key(self) -> None:
        expected = workload("Deployment", "paperless")
        with self.assertRaises(live.InvalidInput):
            live.verify("a: &anchor 1\nb: *anchor", live_list(expected), NAMESPACE)
        with self.assertRaises(live.InvalidInput):
            live.verify("{1: 2}", live_list(expected), NAMESPACE)

    def test_rendered_document_guards(self) -> None:
        expected = workload("Deployment", "paperless")
        with self.assertRaises(live.InvalidInput):
            live.verify("", live_list(expected), NAMESPACE)
        with self.assertRaises(live.InvalidInput):
            live.verify("- 1", live_list(expected), NAMESPACE)
        with self.assertRaises(live.InvalidInput):
            live.verify("a: b: c", live_list(expected), NAMESPACE)
        with patch.object(live, "MAX_RENDERED_BYTES", 4):
            with self.assertRaises(live.InvalidInput):
                live.verify(model(expected), live_list(expected), NAMESPACE)
        with patch.object(live, "MAX_OBJECTS", 1):
            with self.assertRaises(live.InvalidInput):
                live.verify(model(expected, workload("Deployment", "other")), live_list(expected), NAMESPACE)

    def test_rejects_malformed_rendered_workload_specs(self) -> None:
        def rendered(pod_spec: object) -> dict:
            resource = workload("Deployment", "paperless")
            resource["spec"]["template"]["spec"] = pod_spec
            return resource

        invalid_pod_specs = (
            "not-an-object",
            {},
            {"containers": [{"name": "paperless", "image": IMAGE}], "initContainers": "bad"},
            {"containers": ["not-an-object"]},
        )
        for pod_spec in invalid_pod_specs:
            with self.subTest(pod_spec=pod_spec), self.assertRaises(live.WorkloadMismatch):
                live.verify(model(rendered(pod_spec)), live_list(), NAMESPACE)
        bad_template = workload("Deployment", "paperless")
        bad_template["spec"]["template"] = "not-an-object"
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(bad_template), live_list(), NAMESPACE)

    def test_rejects_extra_image_field_and_workload_free_model(self) -> None:
        expected = workload("Deployment", "paperless")
        expected["spec"]["template"]["spec"]["image"] = "stray"
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(expected), live_list(), NAMESPACE)
        configmap = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "settings"}}
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(configmap), live_list(), NAMESPACE)

    def test_rejects_malformed_live_resource_identity(self) -> None:
        expected = workload("Deployment", "paperless")
        bad_live = (
            42,
            {},
            {"apiVersion": "v1", "kind": "Secret"},
        )
        for resource in bad_live:
            with self.subTest(resource=resource), self.assertRaises(live.InvalidInput):
                live.verify(model(expected), live_list(resource), NAMESPACE)
        rendered_out_of_namespace = workload("Deployment", "paperless")
        rendered_out_of_namespace["metadata"]["namespace"] = "other"
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(rendered_out_of_namespace), live_list(expected), NAMESPACE)

    def test_accepts_registry_with_valid_port(self) -> None:
        image = "registry.example.org:5000/docs/paperless@sha256:" + "a" * 64
        expected = workload("Deployment", "paperless", image)
        live.verify(model(expected), live_list(expected), NAMESPACE)

    def test_rejects_reference_with_invalid_digest_and_registry_label(self) -> None:
        invalid_images = (
            "registry.example.org/docs/paperless@sha256:short",
            "Registry.example.org/docs/paperless@sha256:" + "a" * 64,
            "example.org-/docs/paperless@sha256:" + "a" * 64,
        )
        for image in invalid_images:
            expected = workload("Deployment", "paperless", image)
            with self.subTest(image=image), self.assertRaises(live.WorkloadMismatch):
                live.verify(model(expected), live_list(expected), NAMESPACE)

    def test_cronjob_child_template_metadata_guards(self) -> None:
        deployment = workload("Deployment", "paperless")
        live_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID

        not_a_mapping = generated_job(live_cronjob)
        not_a_mapping["spec"]["template"]["metadata"] = []
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment, live_cronjob), live_list(deployment, live_cronjob, not_a_mapping), NAMESPACE)

        bad_labels = generated_job(live_cronjob)
        bad_labels["spec"]["template"]["metadata"] = {"labels": []}
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment, live_cronjob), live_list(deployment, live_cronjob, bad_labels), NAMESPACE)

    def test_accepts_cronjob_child_with_matching_creation_timestamp(self) -> None:
        deployment = workload("Deployment", "paperless")
        reviewed_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        reviewed_cronjob["spec"]["jobTemplate"]["spec"]["template"]["metadata"] = {
            "labels": {"app": "consume"},
            "creationTimestamp": "2020-01-01T00:00:00Z",
        }
        live_cronjob = copy.deepcopy(reviewed_cronjob)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        live.verify(
            model(deployment, reviewed_cronjob),
            live_list(deployment, live_cronjob, child),
            NAMESPACE,
        )

    def test_rejects_cronjob_child_without_unique_owner(self) -> None:
        deployment = workload("Deployment", "paperless")
        live_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        child["metadata"].pop("uid")
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment, live_cronjob), live_list(deployment, live_cronjob, child), NAMESPACE)

    def test_rejects_cronjob_child_with_invalid_owner_name(self) -> None:
        deployment = workload("Deployment", "paperless")
        live_cronjob = workload("CronJob", "consume", BROKER_IMAGE)
        live_cronjob["metadata"]["uid"] = CRONJOB_UID
        child = generated_job(live_cronjob)
        child["metadata"]["ownerReferences"][0]["name"] = ""
        with self.assertRaises(live.WorkloadMismatch):
            live.verify(model(deployment, live_cronjob), live_list(deployment, live_cronjob, child), NAMESPACE)

    def test_verify_rejects_invalid_namespace(self) -> None:
        with self.assertRaises(live.InvalidInput):
            live.verify("x", {}, "Bad_Namespace")

    def test_cli_usage_and_input_guards(self) -> None:
        stderr = io.StringIO()
        with patch.object(sys, "stderr", stderr):
            self.assertEqual(live.main(["verify-live-kubernetes-workloads.py"]), 2)
        empty = type("Input", (), {"buffer": io.BytesIO(b"")})()
        with patch.object(sys, "stdin", empty), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(live.main(["verify-live-kubernetes-workloads.py", NAMESPACE]), 2)
        oversized = type("Input", (), {"buffer": io.BytesIO(b"x" * 16)})()
        with patch.object(live, "MAX_INPUT_BYTES", 4), patch.object(sys, "stdin", oversized), \
                patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(live.main(["verify-live-kubernetes-workloads.py", NAMESPACE]), 2)

    def test_cli_envelope_validation_and_exit_codes(self) -> None:
        expected = workload("Deployment", "paperless")
        rendered = model(expected)

        def stderr_and_exit(raw: bytes) -> tuple[str, int]:
            stream = type("Input", (), {"buffer": io.BytesIO(raw)})()
            stderr = io.StringIO()
            with patch.object(sys, "stdin", stream), patch.object(sys, "stderr", stderr):
                code = live.main(["verify-live-kubernetes-workloads.py", NAMESPACE])
            return stderr.getvalue(), code

        _, invalid_shape = stderr_and_exit(json.dumps({"only": 1}).encode())
        self.assertEqual(invalid_shape, 2)
        _, not_string = stderr_and_exit(
            json.dumps({"rendered_yaml": 5, "live_json": live_list(expected)}).encode()
        )
        self.assertEqual(not_string, 2)
        _, success = stderr_and_exit(
            json.dumps({"rendered_yaml": rendered, "live_json": live_list(expected)}).encode()
        )
        self.assertEqual(success, 0)
        _, drift = stderr_and_exit(
            json.dumps({"rendered_yaml": rendered, "live_json": live_list()}).encode()
        )
        self.assertEqual(drift, 1)

    def test_main_guard_runs_and_exits(self) -> None:
        stream = type("Input", (), {"buffer": io.BytesIO(b"")})()
        with patch.object(sys, "argv", ["verify-live-kubernetes-workloads.py"]), \
                patch.object(sys, "stdin", stream), patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
