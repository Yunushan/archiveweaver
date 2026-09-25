"""Tests for the staged local-only Kustomize closure gate."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-kustomize-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_kustomize_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

ROOT = "/etc/archiveweaver/paperless-ngx/kustomize"


def directory(path: str, mode: str = "0755") -> dict[str, Any]:
    return {"path": path, "uid": 0, "gid": 0, "mode": mode, "isdir": True, "islnk": False}


def staged(files: dict[str, bytes]) -> tuple[dict[str, Any], str]:
    paths: set[str] = set()
    rows: list[dict[str, Any]] = []
    for relative, content in files.items():
        parts = relative.split("/")
        for count in range(1, len(parts)):
            paths.add("/".join(parts[:count]))
        rows.append({
            "item": {
                "path": ROOT + "/" + relative,
                "uid": 0,
                "gid": 0,
                "mode": "0600" if relative.endswith(".env") else "0644",
                "isreg": True,
                "islnk": False,
                "nlink": 1,
                "size": len(content),
                "checksum": hashlib.sha256(content).hexdigest(),
            },
            "encoding": "base64",
            "content": base64.b64encode(content).decode("ascii"),
        })
    dirs = [directory(ROOT + "/" + path) for path in sorted(paths)]
    digest = hashlib.sha256("\n".join(sorted(
        f"{path}:{hashlib.sha256(content).hexdigest()}" for path, content in files.items()
    )).encode("utf-8")).hexdigest()
    envelope = {
        "root": ROOT,
        "ancestors": [directory(path) for path in (
            "/etc", "/etc/archiveweaver", "/etc/archiveweaver/paperless-ngx", ROOT
        )],
        "directories": dirs,
        "all_entries": [*dirs, *(row["item"] for row in rows)],
        "files": rows,
    }
    return envelope, digest


class KustomizeBundleVerifierTests(unittest.TestCase):
    def test_accepts_local_nested_base_and_private_generator_env(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"resources: [base]\nsecretGenerator:\n"
                b"  - name: paperless-env\n    envs: [paperless.env]\n"
            ),
            "paperless.env": b"PAPERLESS_SECRET_KEY=private\n",
            "base/kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"resources: [deployment.yaml]\n"
            ),
            "base/deployment.yaml": b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: paperless\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_rejects_remote_git_base(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"resources: [https://github.com/example/stack//base?ref=main]\n"
            ),
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_out_of_tree_generator_input(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"secretGenerator:\n  - name: env\n    envs: [../paperless.env]\n"
            ),
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_missing_private_generator_input(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"secretGenerator:\n  - name: env\n    envs: [paperless.env]\n"
            ),
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_requires_private_secret_generator_files(self) -> None:
        for source, relative in ((b"envs: [paperless.env]", "paperless.env"),
                                 (b"files: [credentials=secret.txt]", "secret.txt")):
            with self.subTest(source=source):
                envelope, digest = staged({
                    "kustomization.yaml": (
                        b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                        b"secretGenerator:\n  - name: credentials\n    " + source + b"\n"
                    ),
                    relative: b"private",
                })
                for row in envelope["files"]:
                    if row["item"]["path"].endswith(relative):
                        row["item"]["mode"] = "0644"
                with self.assertRaises(VERIFIER.InvalidBundle):
                    VERIFIER.verify(envelope, digest)

    def test_allows_public_configmap_generator_file(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"configMapGenerator:\n  - name: public-settings\n    files: [settings.yaml]\n"
            ),
            "settings.yaml": b"public: true\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_rejects_secret_literals_in_public_kustomization(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": (
                b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                b"secretGenerator:\n  - name: credentials\n    literals: [password=plaintext]\n"
            ),
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_helm_or_plugin_features(self) -> None:
        for field in (b"helmCharts: []", b"generators: [exec.yaml]", b"transformers: [exec.yaml]"):
            with self.subTest(field=field):
                envelope, digest = staged({
                    "kustomization.yaml": (
                        b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                        + field + b"\n"
                    ),
                })
                with self.assertRaises(VERIFIER.InvalidBundle):
                    VERIFIER.verify(envelope, digest)

    def test_rejects_writable_or_nonroot_input(self) -> None:
        files = {
            "kustomization.yaml": b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        }
        for change in ({"mode": "0664"}, {"uid": 1000}, {"gid": 1000}):
            with self.subTest(change=change):
                envelope, digest = staged(files)
                envelope["files"][0]["item"].update(change)
                with self.assertRaises(VERIFIER.InvalidBundle):
                    VERIFIER.verify(envelope, digest)

    def test_rejects_content_changed_after_find(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        })
        envelope["files"][0]["content"] = base64.b64encode(b"changed").decode("ascii")
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_special_or_omitted_tree_entry(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        })
        envelope["all_entries"].append({"path": ROOT + "/socket", "isreg": False})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_duplicate_yaml_keys_and_aliases(self) -> None:
        for content in (
            b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nkind: Kustomization\n",
            b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: &r []\nbases: *r\n",
        ):
            with self.subTest(content=content):
                envelope, digest = staged({"kustomization.yaml": content})
                with self.assertRaises(VERIFIER.InvalidBundle):
                    VERIFIER.verify(envelope, digest)


if __name__ == "__main__":
    unittest.main()
