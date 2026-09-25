"""Check the Paperless v3.2.1 rendered-model admission boundary."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-paperless-rke2-model.py"
SPEC = importlib.util.spec_from_file_location("verify_paperless_rke2_model", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
paperless = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = paperless
SPEC.loader.exec_module(paperless)

NAMESPACE = "documents"
IMAGE = "registry.acme.internal/archive/paperless@sha256:" + "a" * 64
DB_IMAGE = "registry.acme.internal/data/postgresql@sha256:" + "b" * 64
TEST_SECRET_KEY = base64.urlsafe_b64encode(
    hashlib.sha512(b"nonproduction-paperless-contract-test").digest()
).decode("ascii")


def encoded(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def base_model() -> list[dict]:
    return [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "paperless-ngx", "namespace": NAMESPACE},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "template": {
                    "metadata": {"labels": {"app": "paperless-ngx"}},
                    "spec": {
                        "containers": [{
                            "name": "paperless",
                            "image": IMAGE,
                            "ports": [{"name": "http", "containerPort": 8000, "protocol": "TCP"}],
                            "env": [
                                {"name": "PAPERLESS_SECRET_KEY", "valueFrom": {
                                    "secretKeyRef": {"name": "paperless-secrets", "key": "secret-key"}
                                }},
                                {"name": "PAPERLESS_DBENGINE", "value": "postgresql"},
                                {"name": "PAPERLESS_DBHOST", "value": "postgres.data.svc.cluster.local"},
                                {"name": "PAPERLESS_DB_OPTIONS", "value":
                                    "sslmode=verify-full,sslrootcert=/certs/ca.pem"},
                                {"name": "PAPERLESS_REDIS", "valueFrom": {
                                    "secretKeyRef": {"name": "paperless-secrets", "key": "broker-url"}
                                }},
                                {"name": "PAPERLESS_URL", "value": "https://documents.acme.internal"},
                                {"name": "PAPERLESS_DBPASS", "valueFrom": {
                                    "secretKeyRef": {"name": "paperless-secrets", "key": "db-password"}
                                }},
                            ],
                            "volumeMounts": [
                                {"name": "data", "mountPath": "/usr/src/paperless/data"},
                                {"name": "media", "mountPath": "/usr/src/paperless/media"},
                                {"name": "postgres-ca", "mountPath": "/certs", "readOnly": True},
                            ],
                        }],
                        "volumes": [
                            {"name": "data", "persistentVolumeClaim": {"claimName": "paperless-data"}},
                            {"name": "media", "persistentVolumeClaim": {"claimName": "paperless-media"}},
                            {"name": "postgres-ca", "secret": {"secretName": "postgres-ca"}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "paperless", "namespace": NAMESPACE},
            "spec": {
                "selector": {"app": "paperless-ngx"},
                "ports": [{"port": 443, "targetPort": "http", "protocol": "TCP"}],
            },
        },
        {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "paperless-secrets", "namespace": NAMESPACE},
            "data": {
                "secret-key": encoded(TEST_SECRET_KEY),
                "db-password": encoded("synthetic-db-password"),
                "broker-url": encoded("rediss://synthetic-broker.internal:6379"),
                "url": encoded("rediss://synthetic-broker.internal:6379"),
            },
        },
        {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "postgres-ca", "namespace": NAMESPACE},
            "data": {"ca.pem": encoded("synthetic-ca-only")},
        },
    ]


def rendered(objects: list[dict]) -> bytes:
    return "\n---\n".join(json.dumps(item) for item in objects).encode("utf-8")


def app(model: list[dict]) -> dict:
    return model[1]["spec"]["template"]["spec"]["containers"][0]


def env(model: list[dict], name: str) -> dict:
    return next(item for item in app(model)["env"] if item["name"] == name)


class PaperlessRKE2ModelTests(unittest.TestCase):
    def test_accepts_external_dependencies_and_pvc_backed_data_media(self) -> None:
        paperless.verify(rendered(base_model()), NAMESPACE)

    def test_accepts_in_cluster_dependencies_and_secret_file_with_one_pvc(self) -> None:
        model = base_model()
        app_container = app(model)
        app_container["env"] = [
            item for item in app_container["env"] if item["name"] != "PAPERLESS_SECRET_KEY"
        ]
        app_container["env"].append({
            "name": "PAPERLESS_SECRET_KEY_FILE", "value": "/run/secrets/paperless/secret-key"
        })
        app_container["volumeMounts"] = [
            {"name": "paperless-state", "mountPath": "/usr/src/paperless"},
            {"name": "secret-key", "mountPath": "/run/secrets/paperless", "readOnly": True},
            {"name": "postgres-ca", "mountPath": "/certs", "readOnly": True},
        ]
        model[1]["spec"]["template"]["spec"]["volumes"] = [
            {"name": "paperless-state", "persistentVolumeClaim": {"claimName": "paperless-state"}},
            {"name": "secret-key", "secret": {"secretName": "paperless-secrets"}},
            {"name": "postgres-ca", "secret": {"secretName": "postgres-ca"}},
        ]
        config = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "paperless-config", "namespace": NAMESPACE},
            "data": {"db-engine": "postgresql", "public-url": "https://documents.acme.internal"},
        }
        env(model, "PAPERLESS_DBENGINE").pop("value")
        env(model, "PAPERLESS_DBENGINE")["valueFrom"] = {
            "configMapKeyRef": {"name": "paperless-config", "key": "db-engine"}
        }
        env(model, "PAPERLESS_URL").pop("value")
        env(model, "PAPERLESS_URL")["valueFrom"] = {
            "configMapKeyRef": {"name": "paperless-config", "key": "public-url"}
        }
        model.append(config)
        model.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "postgres", "namespace": NAMESPACE},
            "spec": {"template": {"spec": {"containers": [{"name": "db", "image": DB_IMAGE}]}}},
        })
        paperless.verify(rendered(model), NAMESPACE)

    def test_accepts_broker_url_from_required_secret_file(self) -> None:
        model = base_model()
        app_container = app(model)
        app_container["env"] = [
            item for item in app_container["env"] if item["name"] != "PAPERLESS_REDIS"
        ]
        app_container["env"].append({
            "name": "PAPERLESS_REDIS_FILE", "value": "/run/secrets/broker/url"
        })
        app_container["volumeMounts"].append({
            "name": "broker-secret", "mountPath": "/run/secrets/broker", "readOnly": True
        })
        model[1]["spec"]["template"]["spec"]["volumes"].append({
            "name": "broker-secret", "secret": {"secretName": "paperless-secrets"}
        })
        paperless.verify(rendered(model), NAMESPACE)

    def test_accepts_read_only_configmap_postgres_ca(self) -> None:
        model = base_model()
        ca_volume = model[1]["spec"]["template"]["spec"]["volumes"][2]
        ca_volume.pop("secret")
        ca_volume["configMap"] = {
            "name": "postgres-ca", "optional": False,
            "items": [{"key": "approved-ca", "path": "ca.pem"}],
        }
        model.append({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "postgres-ca", "namespace": NAMESPACE},
            "data": {"approved-ca": "synthetic-ca-only"},
        })
        paperless.verify(rendered(model), NAMESPACE)

    def test_accepts_kustomize_wrapped_secret_base64_only_at_line_breaks(self) -> None:
        model = base_model()
        key = model[3]["data"]["secret-key"]
        model[3]["data"]["secret-key"] = "\n".join(
            key[index:index + 70] for index in range(0, len(key), 70)
        )
        paperless.verify(rendered(model), NAMESPACE)
        model[3]["data"]["secret-key"] = key[:70] + " " + key[70:]
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_missing_or_unsafe_settings(self) -> None:
        def set_literal(model: list[dict], name: str, value: str) -> None:
            entry = env(model, name)
            entry.pop("valueFrom", None)
            entry["value"] = value

        changes = {
            "literal secret": lambda model: set_literal(model, "PAPERLESS_SECRET_KEY", "change-me"),
            "optional secret": lambda model: env(model, "PAPERLESS_SECRET_KEY")
                ["valueFrom"]["secretKeyRef"].update({"optional": True}),
            "sqlite default": lambda model: app(model)["env"].remove(env(model, "PAPERLESS_DBENGINE")),
            "wrong database": lambda model: env(model, "PAPERLESS_DBENGINE").update({"value": "sqlite"}),
            "missing host": lambda model: app(model)["env"].remove(env(model, "PAPERLESS_DBHOST")),
            "missing broker": lambda model: app(model)["env"].remove(env(model, "PAPERLESS_REDIS")),
            "literal broker URL": lambda model: set_literal(
                model, "PAPERLESS_REDIS", "redis://valkey.data.svc.cluster.local:6379"
            ),
            "optional broker secret": lambda model: env(model, "PAPERLESS_REDIS")
                ["valueFrom"]["secretKeyRef"].update({"optional": True}),
            "HTTP public URL": lambda model: env(model, "PAPERLESS_URL").update({
                "value": "http://documents.acme.internal"
            }),
            "URL path": lambda model: env(model, "PAPERLESS_URL").update({
                "value": "https://documents.acme.internal/paperless"
            }),
            "literal DB password": lambda model: set_literal(model, "PAPERLESS_DBPASS", "password"),
            "default DB password": lambda model: app(model)["env"].remove(env(model, "PAPERLESS_DBPASS")),
            "optional DB password": lambda model: env(model, "PAPERLESS_DBPASS")
                ["valueFrom"]["secretKeyRef"].update({"optional": True}),
            "unchecked envFrom": lambda model: app(model).update({
                "envFrom": [{"configMapRef": {"name": "unchecked-settings"}}]
            }),
            "auto login": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_AUTO_LOGIN_USERNAME", "value": "admin"
            }),
            "auto login file": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_AUTO_LOGIN_USERNAME_FILE", "value": "/run/secrets/admin"
            }),
            "remote user": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_ENABLE_HTTP_REMOTE_USER", "value": "true"
            }),
            "remote user API": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_ENABLE_HTTP_REMOTE_USER_API", "value": "true"
            }),
            "remote user API file": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_ENABLE_HTTP_REMOTE_USER_API_FILE", "value": "/run/secrets/flag"
            }),
            "DB password file overrides secret": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_DBPASS_FILE", "value": "/run/secrets/other-password"
            }),
        }
        for label, change in changes.items():
            model = base_model()
            change(model)
            with self.subTest(label=label), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_unverified_postgres_tls(self) -> None:
        def set_options(model: list[dict], value: str) -> None:
            env(model, "PAPERLESS_DB_OPTIONS")["value"] = value

        changes = {
            "missing TLS options": lambda model: app(model)["env"].remove(env(model, "PAPERLESS_DB_OPTIONS")),
            "disabled TLS": lambda model: set_options(model, "sslmode=disable,sslrootcert=/certs/ca.pem"),
            "unverified TLS": lambda model: set_options(model, "sslmode=require,sslrootcert=/certs/ca.pem"),
            "CA only verification": lambda model: set_options(model, "sslmode=verify-ca,sslrootcert=/certs/ca.pem"),
            "missing CA path": lambda model: set_options(model, "sslmode=verify-full"),
            "placeholder CA path": lambda model: set_options(
                model, "sslmode=verify-full,sslrootcert=/certs/REPLACE_WITH_CA.pem"
            ),
            "duplicate mode": lambda model: set_options(
                model, "sslmode=verify-full,sslmode=disable,sslrootcert=/certs/ca.pem"
            ),
            "TLS options file overrides reviewed value": lambda model: app(model)["env"].append({
                "name": "PAPERLESS_DB_OPTIONS_FILE", "value": "/run/secrets/db-options"
            }),
            "unmounted CA": lambda model: app(model)["volumeMounts"].pop(),
            "writable CA mount": lambda model: app(model)["volumeMounts"][2].update({"readOnly": False}),
            "PVC masquerades as CA": lambda model: model[1]["spec"]["template"]["spec"]
                ["volumes"][2].update({"secret": None,
                    "persistentVolumeClaim": {"claimName": "paperless-media"}}),
            "optional CA": lambda model: model[1]["spec"]["template"]["spec"]
                ["volumes"][2]["secret"].update({"optional": True}),
            "CA key projected elsewhere": lambda model: model[1]["spec"]["template"]["spec"]
                ["volumes"][2]["secret"].update({
                    "items": [{"key": "approved-ca", "path": "elsewhere.pem"}]
                }),
        }
        for label, change in changes.items():
            model = base_model()
            change(model)
            with self.subTest(label=label), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_file_overrides_of_reviewed_direct_settings(self) -> None:
        for name in (
            "PAPERLESS_URL_FILE", "PAPERLESS_DBHOST_FILE", "PAPERLESS_DBENGINE_FILE",
            "PAPERLESS_DATA_DIR_FILE", "PAPERLESS_MEDIA_ROOT_FILE",
            "PAPERLESS_DBPORT_FILE", "PAPERLESS_ADMIN_USER_FILE",
        ):
            model = base_model()
            app(model)["env"].append({"name": name, "value": "/run/secrets/override"})
            with self.subTest(name=name), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_missing_or_weak_first_use_secret_material(self) -> None:
        changes = {
            "missing app Secret": lambda model: model.pop(3),
            "missing DB password key": lambda model: model[3]["data"].pop("db-password"),
            "empty DB password": lambda model: model[3]["data"].update({"db-password": ""}),
            "missing CA Secret": lambda model: model.pop(4),
            "missing CA key": lambda model: model[4]["data"].pop("ca.pem"),
            "short application key": lambda model: model[3]["data"].update({
                "secret-key": encoded("short")
            }),
            "obvious application key": lambda model: model[3]["data"].update({
                "secret-key": encoded("change-me-this-is-not-a-real-secret-key-123456789")
            }),
            "low-diversity key": lambda model: model[3]["data"].update({
                "secret-key": encoded("a" * 64)
            }),
        }
        for label, change in changes.items():
            model = base_model()
            change(model)
            with self.subTest(label=label), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_unresolved_markers_in_any_field_and_encoded_secret(self) -> None:
        for location in ("storage", "cidr", "secret"):
            model = base_model()
            if location == "storage":
                model.append({
                    "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                    "metadata": {"name": "paperless-data", "namespace": NAMESPACE},
                    "spec": {"storageClassName": "REPLACE_WITH_STORAGE_CLASS"},
                })
            elif location == "cidr":
                model.append({
                    "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": "paperless", "namespace": NAMESPACE},
                    "spec": {"egress": [{"to": [{"ipBlock": {"cidr": "replace_with_cidr"}}]}]},
                })
            else:
                model.append({
                    "apiVersion": "v1", "kind": "Secret",
                    "metadata": {"name": "paperless-secrets", "namespace": NAMESPACE},
                    "data": {"broker-url": base64.b64encode(
                        b"redis://REPLACE_WITH_BROKER_HOST:6379"
                    ).decode("ascii")},
                })
            with self.subTest(location=location), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_invalid_encoded_secret_without_disclosing_value(self) -> None:
        model = base_model()
        model.append({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "paperless-secrets", "namespace": NAMESPACE},
            "data": {"broker-url": "%%not-base64%%"},
        })
        stderr = io.StringIO()
        data = type("Input", (), {"buffer": io.BytesIO(rendered(model))})()
        with patch.object(sys, "stdin", data), patch.object(sys, "stderr", stderr):
            self.assertEqual(paperless.main(["verify-paperless-rke2-model.py", NAMESPACE]), 1)
        self.assertNotIn("%%not-base64%%", stderr.getvalue())

    def test_rejects_overlap_port_and_storage_gaps(self) -> None:
        changes = {
            "two replicas": lambda model: model[1]["spec"].update({"replicas": 2}),
            "rolling update": lambda model: model[1]["spec"].update({"strategy": {"type": "RollingUpdate"}}),
            "wrong container port": lambda model: app(model)["ports"][0].update({"containerPort": 8080}),
            "wrong Service port": lambda model: model[2]["spec"]["ports"][0].update({"targetPort": 8080}),
            "wrong Service selector": lambda model: model[2]["spec"].update({"selector": {"app": "wrong"}}),
            "emptyDir data": lambda model: model[1]["spec"]["template"]["spec"]["volumes"][0]
                .update({"persistentVolumeClaim": None, "emptyDir": {}}),
            "read-only media": lambda model: app(model)["volumeMounts"][1].update({"readOnly": True}),
            "missing media mount": lambda model: app(model)["volumeMounts"].pop(1),
        }
        for label, change in changes.items():
            model = base_model()
            change(model)
            with self.subTest(label=label), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_shadow_mount_autoscaler_and_second_full_app(self) -> None:
        model = base_model()
        app(model)["volumeMounts"].append({
            "name": "scratch", "mountPath": "/usr/src/paperless/data", "readOnly": False
        })
        model[1]["spec"]["template"]["spec"]["volumes"].append({"name": "scratch", "emptyDir": {}})
        app(model)["volumeMounts"][0]["mountPath"] = "/usr/src/paperless"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model.append({
            "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "paperless-hpa", "namespace": NAMESPACE},
            "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "paperless-ngx"}},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        duplicate = copy.deepcopy(model[1])
        duplicate["kind"] = "StatefulSet"
        model.append(duplicate)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_second_paperless_even_with_another_digest_or_workload_kind(self) -> None:
        model = base_model()
        duplicate = copy.deepcopy(model[1])
        duplicate["metadata"]["name"] = "paperless-shadow"
        duplicate["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "registry.acme.internal/archive/paperless@sha256:" + "c" * 64
        )
        model.append(duplicate)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        for kind, template_spec in (
            ("Job", {"template": {"spec": {"containers": [{
                "name": "other", "image": "ghcr.io/paperless-ngx/paperless-ngx@sha256:" + "d" * 64
            }]}}}),
            ("CronJob", {"jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "other", "image": IMAGE}]
            }}}}}),
        ):
            model = base_model()
            model.append({
                "apiVersion": "batch/v1", "kind": kind,
                "metadata": {"name": "background-task", "namespace": NAMESPACE},
                "spec": template_spec,
            })
            with self.subTest(kind=kind), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_allows_separate_database_and_broker_workloads(self) -> None:
        model = base_model()
        for kind, name, image in (
            ("StatefulSet", "postgres", DB_IMAGE),
            ("Deployment", "valkey", "registry.acme.internal/data/valkey@sha256:" + "c" * 64),
        ):
            model.append({
                "apiVersion": "apps/v1", "kind": kind,
                "metadata": {"name": name, "namespace": NAMESPACE,
                             "labels": {"app.kubernetes.io/name": name,
                                        "app.kubernetes.io/part-of": "paperless-ngx"}},
                "spec": {"template": {"spec": {"containers": [{"name": name, "image": image}]}}},
            })
        paperless.verify(rendered(model), NAMESPACE)

    def test_rejects_untrusted_yaml_and_namespace(self) -> None:
        model = base_model()
        model[1]["metadata"]["namespace"] = "other"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        with self.assertRaises(paperless.InvalidInput):
            paperless.verify(rendered(base_model()).replace(b'"kind": "Deployment",',
                b'"kind": "Deployment", "kind": "Job",'), NAMESPACE)
        with self.assertRaises(paperless.InvalidInput):
            paperless.verify(b"a: &anchor value\nb: *anchor\n", NAMESPACE)
        with self.assertRaises(paperless.InvalidInput):
            paperless.verify(rendered(base_model()), "../other")

    def test_cli_exit_codes(self) -> None:
        good = type("Input", (), {"buffer": io.BytesIO(rendered(base_model()))})()
        with patch.object(sys, "stdin", good), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(paperless.main(["verify-paperless-rke2-model.py", NAMESPACE]), 0)
        bad = type("Input", (), {"buffer": io.BytesIO(b"garbage")})()
        with patch.object(sys, "stdin", bad), patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(paperless.main(["verify-paperless-rke2-model.py", NAMESPACE]), 2)
        self.assertEqual(paperless.main(["verify-paperless-rke2-model.py"]), 2)


if __name__ == "__main__":
    unittest.main()
