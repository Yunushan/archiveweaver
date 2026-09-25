"""Contract checks for the intentionally incomplete Paperless v3.2.1 bundle."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "deploy" / "paperless-ngx" / "rke2"
ALLOWED_FIRST_USE = {
    ("v1", "Namespace"),
    ("v1", "ServiceAccount"),
    ("v1", "PersistentVolumeClaim"),
    ("v1", "Service"),
    ("apps/v1", "Deployment"),
    ("networking.k8s.io/v1", "NetworkPolicy"),
}


def _documents(name: str) -> list[dict[str, Any]]:
    values = list(yaml.safe_load_all((BUNDLE / name).read_text(encoding="utf-8")))
    if not values or not all(isinstance(value, dict) for value in values):
        raise AssertionError(f"{name} must contain Kubernetes object mappings")
    return values


def _one(name: str) -> dict[str, Any]:
    values = _documents(name)
    if len(values) != 1:
        raise AssertionError(f"{name} must contain one object")
    return values[0]


class PaperlessRke2BundleTest(unittest.TestCase):
    def test_kustomization_requires_local_untracked_secret_and_compatible_scope(self) -> None:
        kustomization = _one("kustomization.yaml")
        self.assertEqual(kustomization["kind"], "Kustomization")
        self.assertEqual(kustomization["namespace"], "archiveweaver")
        self.assertEqual(
            kustomization["secretGenerator"],
            [
                {"name": "paperless-ngx-secrets", "envs": ["paperless.env"]},
                {"name": "paperless-postgres-ca", "files": ["ca.pem=postgres-ca.pem"]},
            ],
        )
        self.assertFalse((BUNDLE / "paperless.env").exists())
        self.assertFalse((BUNDLE / "postgres-ca.pem").exists())
        ignored = (BUNDLE / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/paperless.env", ignored)
        self.assertIn("/postgres-ca.pem", ignored)
        self.assertNotIn("ingress.yaml.example", kustomization["resources"])
        self.assertEqual(
            set(kustomization["resources"]),
            {"namespace.yaml", "serviceaccount.yaml", "pvc.yaml", "deployment.yaml",
             "service.yaml", "networkpolicy.yaml"},
        )

        objects = [item for name in kustomization["resources"] for item in _documents(name)]
        self.assertTrue(objects)
        for item in objects:
            with self.subTest(kind=item["kind"], name=item["metadata"]["name"]):
                self.assertIn((item["apiVersion"], item["kind"]), ALLOWED_FIRST_USE)
                self.assertRegex(item["metadata"]["name"], r"^[a-z0-9][a-z0-9.-]{0,252}$")
                self.assertNotIn("namespace", item["metadata"])
        self.assertEqual(_one("namespace.yaml")["metadata"]["name"], "archiveweaver")
        self.assertEqual(_one("deployment.yaml")["metadata"]["name"], "paperless-ngx")

    def test_single_rootless_paperless_process_and_dependency_configuration(self) -> None:
        deployment = _one("deployment.yaml")
        spec = deployment["spec"]
        self.assertEqual(spec["replicas"], 1)
        self.assertEqual(spec["strategy"]["type"], "Recreate")
        pod = spec["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "paperless-ngx")
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["securityContext"]["runAsUser"], 1000)
        self.assertEqual(pod["securityContext"]["runAsGroup"], 1000)
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["fsGroup"], 1000)
        self.assertEqual(len(pod["containers"]), 1)
        container = pod["containers"][0]
        self.assertEqual(container["ports"][0]["containerPort"], 8000)
        self.assertIn("@sha256:REPLACE_WITH_APPROVED_IMAGE_DIGEST", container["image"])
        self.assertNotIn("envFrom", container)
        entries = {entry["name"]: entry for entry in container["env"]}
        self.assertEqual(len(entries), len(container["env"]))
        self.assertEqual(entries["PAPERLESS_DBENGINE"]["value"], "postgresql")
        self.assertEqual(entries["PAPERLESS_DBHOST"]["value"], "REPLACE_WITH_APPROVED_POSTGRES_HOST")
        self.assertEqual(entries["PAPERLESS_URL"]["value"], "https://REPLACE_WITH_PUBLIC_HOST")
        self.assertEqual(entries["PAPERLESS_DB_OPTIONS"]["value"],
                         "sslmode=verify-full,sslrootcert=/certs/ca.pem")
        self.assertNotIn("USERMAP_UID", entries)
        self.assertNotIn("USERMAP_GID", entries)
        for name in ("PAPERLESS_SECRET_KEY", "PAPERLESS_DBPASS", "PAPERLESS_REDIS",
                     "PAPERLESS_ADMIN_USER", "PAPERLESS_ADMIN_PASSWORD", "PAPERLESS_ADMIN_MAIL"):
            self.assertEqual(
                entries[name],
                {"name": name, "valueFrom": {"secretKeyRef": {
                    "name": "paperless-ngx-secrets", "key": name}}},
            )
        for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
            probe = container[probe_name]
            self.assertNotIn("httpGet", probe)
            self.assertIn("http://localhost:8000/", probe["exec"]["command"])
        self.assertEqual(_one("service.yaml")["spec"]["ports"][0]["port"], 8000)
        self.assertEqual(
            {entry["name"]: entry for entry in container["volumeMounts"]}["postgres-ca"],
            {"name": "postgres-ca", "mountPath": "/certs", "readOnly": True},
        )
        self.assertEqual(
            {entry["name"]: entry for entry in pod["volumes"]}["postgres-ca"]["secret"],
            {"secretName": "paperless-postgres-ca", "optional": False,
             "items": [{"key": "ca.pem", "path": "ca.pem"}]},
        )

    def test_four_persistent_paths_and_unresolved_csi_selection(self) -> None:
        container = _one("deployment.yaml")["spec"]["template"]["spec"]["containers"][0]
        mounts = {entry["name"]: entry["mountPath"] for entry in container["volumeMounts"]
                  if entry["name"] != "postgres-ca"}
        self.assertEqual(
            mounts,
            {name: f"/usr/src/paperless/{name}" for name in ("data", "media", "consume", "export")},
        )
        claims = {
            entry["name"]: entry["persistentVolumeClaim"]["claimName"]
            for entry in _one("deployment.yaml")["spec"]["template"]["spec"]["volumes"]
            if "persistentVolumeClaim" in entry
        }
        self.assertEqual(claims, {name: f"paperless-ngx-{name}" for name in mounts})
        pvcs = _documents("pvc.yaml")
        self.assertEqual({pvc["metadata"]["name"] for pvc in pvcs}, set(claims.values()))
        for pvc in pvcs:
            self.assertEqual(pvc["spec"]["accessModes"], ["ReadWriteOnce"])
            self.assertEqual(
                pvc["spec"]["storageClassName"], "REPLACE_WITH_APPROVED_CSI_STORAGE_CLASS"
            )
            self.assertTrue(pvc["spec"]["resources"]["requests"]["storage"].startswith("REPLACE_WITH_"))

    def test_network_policy_stays_scoped_to_required_paths(self) -> None:
        policies = {entry["metadata"]["name"]: entry for entry in _documents("networkpolicy.yaml")}
        self.assertEqual(
            policies["paperless-ngx-default-deny"]["spec"],
            {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        )
        allowed = policies["paperless-ngx-allow-approved-traffic"]["spec"]
        self.assertEqual(allowed["podSelector"]["matchLabels"]["app.kubernetes.io/name"], "paperless-ngx")
        ingress = allowed["ingress"]
        self.assertEqual(len(ingress), 1)
        self.assertEqual(ingress[0]["from"][0]["ipBlock"]["cidr"],
                         "REPLACE_WITH_APPROVED_INGRESS_SOURCE_CIDR")
        self.assertEqual(ingress[0]["ports"], [{"protocol": "TCP", "port": 8000}])
        egress = allowed["egress"]
        self.assertEqual(len(egress), 3)
        self.assertEqual({port["port"] for row in egress for port in row["ports"]}, {53, 5432, 6379})
        cidrs = [to["ipBlock"]["cidr"] for row in egress for to in row["to"] if "ipBlock" in to]
        self.assertEqual(set(cidrs), {"REPLACE_WITH_APPROVED_POSTGRES_CIDR",
                                      "REPLACE_WITH_APPROVED_VALKEY_CIDR"})
        self.assertNotIn("0.0.0.0/0", str(allowed))
        self.assertNotIn("::/0", str(allowed))

    def test_public_ingress_and_secret_inputs_remain_review_templates(self) -> None:
        ingress = _one("ingress.yaml.example")
        self.assertEqual(ingress["spec"]["rules"][0]["host"], "REPLACE_WITH_PUBLIC_HOST")
        self.assertEqual(ingress["spec"]["tls"][0]["hosts"], ["REPLACE_WITH_PUBLIC_HOST"])
        self.assertEqual(ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"]["number"], 8000)
        example = (BUNDLE / "paperless.env.example").read_text(encoding="utf-8")
        keys = dict(re.findall(r"(?m)^([A-Z_]+)=(\S+)$", example))
        self.assertEqual(set(keys), {"PAPERLESS_SECRET_KEY", "PAPERLESS_DBPASS", "PAPERLESS_REDIS",
                                     "PAPERLESS_ADMIN_USER", "PAPERLESS_ADMIN_PASSWORD", "PAPERLESS_ADMIN_MAIL"})
        self.assertTrue(all(value.startswith("REPLACE_WITH_") for value in keys.values()))
        ca_example = (BUNDLE / "postgres-ca.pem.example").read_text(encoding="utf-8")
        self.assertIn("approved PostgreSQL server CA", ca_example)
        self.assertNotIn("BEGIN CERTIFICATE", ca_example)


if __name__ == "__main__":
    unittest.main()
