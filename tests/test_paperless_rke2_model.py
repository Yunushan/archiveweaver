"""Check the Paperless v3.2.1 rendered-model admission boundary."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import runpy
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

    def test_import_without_pyyaml_fails_deterministically(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_paperless_rke2_model_no_yaml", SCRIPT
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"yaml": None}):
            sys.modules[spec.name] = module
            try:
                spec.loader.exec_module(module)
            finally:
                sys.modules.pop(spec.name, None)
        self.assertIsNone(module.yaml)
        with self.assertRaises(module.InvalidInput):
            module._documents(b"kind: ConfigMap\n")

    def test_secret_data_decoding_limits_and_ambiguity(self) -> None:
        with self.assertRaises(paperless.ModelRejected):
            paperless._decode_secret_data(None)
        with self.assertRaises(paperless.ModelRejected):
            paperless._decode_secret_data("a" * (paperless.MAX_SECRET_VALUE_BYTES * 2 + 1))
        oversized = base64.b64encode(b"a" * (paperless.MAX_SECRET_VALUE_BYTES + 1)).decode()
        with self.assertRaises(paperless.ModelRejected):
            paperless._decode_secret_data(oversized)

        objects = {("Secret", "s"): {
            "apiVersion": "v1", "data": {"k": encoded("one")}, "stringData": {"k": "one"},
        }}
        with self.assertRaises(paperless.ModelRejected):
            paperless._secret_material(objects, "s", "k", "label")

        objects = {("Secret", "s"): {"apiVersion": "v1", "stringData": {"k": "material"}}}
        self.assertEqual(paperless._secret_material(objects, "s", "k", "label"), b"material")
        with patch.object(paperless, "MAX_SECRET_VALUE_BYTES", 4):
            objects = {("Secret", "s"): {"apiVersion": "v1", "stringData": {"k": "longer"}}}
            with self.assertRaises(paperless.ModelRejected):
                paperless._secret_material(objects, "s", "k", "label")

    def test_yaml_loader_and_structure_limits(self) -> None:
        loader = paperless._StrictLoader("")
        node = paperless.yaml.ScalarNode("tag:yaml.org,2002:str", "value")
        with self.assertRaises(paperless.InvalidInput):
            loader.construct_mapping(node)
        loader.dispose()
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(b"1: value\n")
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(b"")
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(b"# only a comment\n")
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(b"a: [b\n")
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(b"\xff\xfe")
        documents = b"a: 1\n" + b"---\na: 1\n" * paperless.MAX_DOCUMENTS
        with self.assertRaises(paperless.InvalidInput):
            paperless._documents(documents)
        with patch.object(paperless, "MAX_NODES", 0):
            with self.assertRaises(paperless.InvalidInput):
                paperless._documents(rendered(base_model()))
        with patch.object(paperless, "MAX_DEPTH", -1):
            with self.assertRaises(paperless.InvalidInput):
                paperless._documents(rendered(base_model()))
        secret = {"apiVersion": "v1", "kind": "Secret",
                  "metadata": {"name": "s", "namespace": NAMESPACE}, "data": []}
        with self.assertRaises(paperless.ModelRejected):
            paperless._documents(rendered([secret]))

    def test_object_identity_and_heading_validation(self) -> None:
        bad_identity = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {}}
        with self.assertRaises(paperless.InvalidInput):
            paperless._objects([bad_identity], NAMESPACE)
        wrong_namespace = {"apiVersion": "v1", "kind": "Namespace",
                           "metadata": {"name": "other"}}
        with self.assertRaises(paperless.ModelRejected):
            paperless._objects([wrong_namespace], NAMESPACE)
        namespaced = {"apiVersion": "v1", "kind": "Namespace",
                      "metadata": {"name": NAMESPACE, "namespace": NAMESPACE}}
        with self.assertRaises(paperless.ModelRejected):
            paperless._objects([namespaced], NAMESPACE)
        duplicate = {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": "duplicate", "namespace": NAMESPACE}}
        with self.assertRaises(paperless.InvalidInput):
            paperless._objects([duplicate, copy.deepcopy(duplicate)], NAMESPACE)
        with self.assertRaises(paperless.ModelRejected):
            paperless._mapping([], "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._list(None, "label")

        model = base_model()
        app(model)["env"].append({"value": "missing-name"})
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        app(model)["env"].append({"name": "PAPERLESS_URL", "value": "duplicate"})
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        app(model)["env"].append({
            "name": "PAPERLESS_EXTRA", "value": "x",
            "valueFrom": {"configMapKeyRef": {"name": "paperless-config", "key": "x"}},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_static_value_reference_rejections(self) -> None:
        def set_reference(model: list[dict], reference: object) -> None:
            entry = env(model, "PAPERLESS_DBENGINE")
            entry.pop("value")
            entry["valueFrom"] = reference

        changes = {
            "wrong reference source": lambda model: set_reference(
                model, {"unknownSource": {"name": "paperless-secrets", "key": "db-engine"}}
            ),
            "optional config reference": lambda model: set_reference(
                model, {"configMapKeyRef": {
                    "name": "paperless-config", "key": "db-engine", "optional": True
                }}
            ),
            "unnamed config reference": lambda model: set_reference(
                model, {"configMapKeyRef": {"name": "", "key": "db-engine"}}
            ),
        }
        for label, change in changes.items():
            model = base_model()
            change(model)
            with self.subTest(label=label), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        set_reference(model, {"configMapKeyRef": {
            "name": "absent-config", "key": "db-engine"
        }})
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        set_reference(model, {"configMapKeyRef": {
            "name": "postgres-ca", "key": "db-engine"
        }})
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_secret_string_data_and_projected_keys(self) -> None:
        model = base_model()
        model[3]["stringData"] = {"secret-key": TEST_SECRET_KEY}
        model[3]["data"].pop("secret-key")
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[3]["stringData"] = {"secret-key": ""}
        model[3]["data"].pop("secret-key")
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        with self.assertRaises(paperless.ModelRejected):
            paperless._projected_key({}, "../escape", "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._projected_key({}, "nested/file", "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._projected_key({"items": "not-a-list"}, "file", "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._projected_key({"items": [{"path": "file", "key": 1}]}, "file", "label")

    def test_review_secret_volume_error_paths(self) -> None:
        with self.assertRaises(paperless.ModelRejected):
            paperless._review_secret_references({}, {"volumes": [1]}, {})
        with self.assertRaises(paperless.ModelRejected):
            paperless._review_secret_references(
                {}, {"volumes": [{"name": "v", "secret": {"secretName": 1}}]}, {}
            )
        secret = {"apiVersion": "v1", "kind": "Secret",
                  "metadata": {"name": "s", "namespace": NAMESPACE},
                  "data": {"k": encoded("value")}}
        objects = {("Secret", "s"): secret}
        with self.assertRaises(paperless.ModelRejected):
            paperless._review_secret_references(
                {}, {"volumes": [{"name": "v", "secret": {"secretName": "s", "items": []}}]},
                objects,
            )
        with self.assertRaises(paperless.ModelRejected):
            paperless._review_secret_references(
                {}, {"volumes": [{"name": "v", "secret": {"secretName": "s", "items": [1]}}]},
                objects,
            )
        with self.assertRaises(paperless.ModelRejected):
            paperless._review_secret_references(
                {}, {"volumes": [{"name": "v", "secret": {
                    "secretName": "s", "items": [{"key": 1}]
                }}]}, objects,
            )
        paperless._review_secret_references(
            {}, {"volumes": [{"name": "v", "secret": {
                "secretName": "s", "items": [{"key": "k"}]
            }}]}, objects,
        )

    def test_absolute_path_and_mount_validation(self) -> None:
        with self.assertRaises(paperless.ModelRejected):
            paperless._absolute_path("/", "label")
        container = {"volumeMounts": [{"name": "v", "mountPath": "/data"}]}
        with self.assertRaises(paperless.ModelRejected):
            paperless._covering_mount("/data/file", container, {"volumes": [1]}, "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._covering_mount(
                "/data/file", container,
                {"volumes": [{"name": "v"}, {"name": "v"}]}, "label",
            )
        with self.assertRaises(paperless.ModelRejected):
            paperless._covering_mount("/data/file", {"volumeMounts": [1]},
                                      {"volumes": [{"name": "v"}]}, "label")
        with self.assertRaises(paperless.ModelRejected):
            paperless._covering_mount(
                "/data/file", {"volumeMounts": [{"name": "other", "mountPath": "/data"}]},
                {"volumes": [{"name": "v"}]}, "label",
            )

    def test_secret_file_error_paths(self) -> None:
        model = base_model()
        app_container = app(model)
        app_container["env"] = [
            item for item in app_container["env"] if item["name"] != "PAPERLESS_SECRET_KEY"
        ]
        app_container["env"].append({
            "name": "PAPERLESS_SECRET_KEY_FILE",
            "valueFrom": {"secretKeyRef": {"name": "paperless-secrets", "key": "secret-key"}},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        for path, optional in (
            ("/run/secrets/paperless", False),
            ("/run/secrets/paperless/secret-key", True),
        ):
            model = base_model()
            app_container = app(model)
            app_container["env"] = [
                item for item in app_container["env"]
                if item["name"] != "PAPERLESS_SECRET_KEY"
            ]
            app_container["env"].append(
                {"name": "PAPERLESS_SECRET_KEY_FILE", "value": path}
            )
            app_container["volumeMounts"].append({
                "name": "secret-key", "mountPath": "/run/secrets/paperless", "readOnly": True
            })
            model[1]["spec"]["template"]["spec"]["volumes"].append({
                "name": "secret-key",
                "secret": {"secretName": "paperless-secrets", "optional": optional},
            })
            with self.subTest(path=path, optional=optional), \
                    self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

    def test_secret_key_source_and_encoding_failures(self) -> None:
        model = base_model()
        app(model)["env"].append({
            "name": "PAPERLESS_SECRET_KEY_FILE",
            "value": "/run/secrets/paperless/secret-key",
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        app(model)["env"] = [
            item for item in app(model)["env"]
            if item["name"] != "PAPERLESS_SECRET_KEY"
        ]
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[3]["data"]["secret-key"] = base64.b64encode(b"\xff" * 40).decode()
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_url_and_database_tls_error_paths(self) -> None:
        for value in (
            "",
            "https://documents.acme.internal ",
            "https://replace_with_host",
            "https://documents.acme.internal:not-a-port",
        ):
            model = base_model()
            env(model, "PAPERLESS_URL")["value"] = value
            with self.subTest(value=value), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)

        with self.assertRaises(paperless.ModelRejected):
            paperless._database_tls(
                {"PAPERLESS_DB_OPTIONS_FILE": {"value": "/run/secrets/options"}},
                {}, {}, {},
            )

        model = base_model()
        env(model, "PAPERLESS_DB_OPTIONS")["value"] = (
            "sslmode=verify-full,sslrootcert=/certs/ca.pem/"
        )
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        env(model, "PAPERLESS_DB_OPTIONS")["value"] = (
            "sslmode=verify-full,sslrootcert=/certs"
        )
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_broker_rejects_both_direct_and_file_sources(self) -> None:
        with self.assertRaises(paperless.ModelRejected):
            paperless._broker(
                {
                    "PAPERLESS_REDIS": {"value": "redis://broker:6379"},
                    "PAPERLESS_REDIS_FILE": {"value": "/run/secrets/redis"},
                },
                {}, {}, {},
            )

    def test_configmap_ca_missing_key_and_binary_data(self) -> None:
        model = base_model()
        ca_volume = model[1]["spec"]["template"]["spec"]["volumes"][2]
        ca_volume.pop("secret")
        ca_volume["configMap"] = {"name": "postgres-ca"}
        model.append({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "postgres-ca", "namespace": NAMESPACE},
            "data": {"other": "value"},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        ca_volume = model[1]["spec"]["template"]["spec"]["volumes"][2]
        ca_volume.pop("secret")
        ca_volume["configMap"] = {"name": "postgres-ca"}
        model.append({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "postgres-ca", "namespace": NAMESPACE},
            "binaryData": {"ca.pem": encoded("synthetic-ca-only")},
        })
        paperless.verify(rendered(model), NAMESPACE)

    def test_app_container_and_port_shape_errors(self) -> None:
        model = base_model()
        pod = model[1]["spec"]["template"]["spec"]
        pod["containers"].insert(0, {"name": "sidecar", "image": DB_IMAGE})
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[1]["spec"]["template"]["spec"]["containers"].append(1)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        duplicate = copy.deepcopy(app(model))
        model[1]["spec"]["template"]["spec"]["containers"].append(duplicate)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        app(model)["ports"].append(1)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        app(model)["ports"].append({"containerPort": 8000, "protocol": "TCP"})
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[1]["spec"]["template"]["metadata"]["labels"] = {}
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[2]["spec"] = "not-a-mapping"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model[2]["spec"]["ports"] = "not-a-list"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_secondary_workload_shape_errors(self) -> None:
        model = base_model()
        model.append({
            "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "other-hpa", "namespace": NAMESPACE},
            "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "other"}},
        })
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "other", "namespace": NAMESPACE},
            "spec": {"template": {"spec": []}},
        })
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "other", "namespace": NAMESPACE},
            "spec": {"template": {"spec": {"containers": [1]}}},
        })
        paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "other", "namespace": NAMESPACE,
                         "labels": {"app": "paperless-ngx"}},
            "spec": {"template": {"spec": {"containers": []}}},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

        model = base_model()
        model.append({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "other", "namespace": NAMESPACE},
            "spec": {"template": {"metadata": {"labels": {"k8s-app": "paperless-ngx"}},
                                  "spec": {"containers": []}}},
        })
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)

    def test_verify_rejects_missing_deployment_and_bad_host(self) -> None:
        model = base_model()
        model.pop(1)
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        model[1]["apiVersion"] = "apps/v1beta1"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        app(model)["image"] = "registry.acme.internal/archive/paperless:latest"
        with self.assertRaises(paperless.ModelRejected):
            paperless.verify(rendered(model), NAMESPACE)
        for host in ("", "replace_with_db_host", "example.invalid"):
            model = base_model()
            env(model, "PAPERLESS_DBHOST")["value"] = host
            with self.subTest(host=host), self.assertRaises(paperless.ModelRejected):
                paperless.verify(rendered(model), NAMESPACE)
        model = base_model()
        app(model)["env"].append({
            "name": "PAPERLESS_ADMIN_PASSWORD",
            "valueFrom": {"secretKeyRef": {"name": "paperless-secrets", "key": "db-password"}},
        })
        paperless.verify(rendered(model), NAMESPACE)

    def test_module_main_guard(self) -> None:
        stdin = type("Input", (), {"buffer": io.BytesIO(rendered(base_model()))})()
        with patch.object(sys, "argv", ["verify-paperless-rke2-model.py", NAMESPACE]), \
                patch.object(sys, "stdin", stdin), patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
