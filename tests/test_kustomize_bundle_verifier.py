"""Tests for the staged local-only Kustomize closure gate."""

from __future__ import annotations

import base64
import builtins
import hashlib
import importlib.util
import io
import json
import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-kustomize-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_kustomize_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

ROOT = "/etc/archiveweaver/paperless-ngx/kustomize"
VALID_KUST = b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"


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

    def test_strict_loader_rejects_non_mapping_node(self) -> None:
        loader = VERIFIER._StrictLoader("")
        try:
            node = yaml.SequenceNode(tag="tag:yaml.org,2002:seq", value=[])
            with self.assertRaises(VERIFIER.InvalidBundle):
                loader.construct_mapping(node)
        finally:
            loader.dispose()

    def test_json_no_duplicates_rejects_repeated_key(self) -> None:
        self.assertEqual(VERIFIER._json_no_duplicates([("a", 1), ("b", 2)]), {"a": 1, "b": 2})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER._json_no_duplicates([("a", 1), ("a", 2)])

    def test_safe_relative_rejects_nonportable_paths(self) -> None:
        for value in ("", "..", "/abs", "a//b", "a/./b", 5):
            with self.subTest(value=value), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER._safe_relative(value)

    def test_entry_path_rejects_outside_root(self) -> None:
        for value in ("/other/x", ROOT, 5):
            with self.subTest(value=value), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER._entry_path(ROOT, value)

    def test_protected_mode_rejects_invalid_entries(self) -> None:
        base = {"uid": 0, "gid": 0, "mode": "0755", "islnk": False}
        for entry, directory in (
            ({**base, "mode": "8888"}, False),
            ({**base, "mode": "0600"}, True),
            ({**base, "islnk": True}, False),
        ):
            with self.subTest(entry=entry), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER._protected_mode(entry, directory=directory)

    def test_local_path_rejects_nonlocal_references(self) -> None:
        for value in ("/abs", "a//b", "", 5):
            with self.subTest(value=value), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER._local_path("base", value)

    def test_paths_rejects_non_list_values(self) -> None:
        self.assertEqual(VERIFIER._paths(None, "label"), [])
        for value in ("x", [1], {"a": 1}):
            with self.subTest(value=value), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER._paths(value, "label")

    def test_verify_rejects_invalid_approved_digest(self) -> None:
        envelope, _ = staged({"kustomization.yaml": VALID_KUST})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, "not-a-digest")

    def test_verify_rejects_bad_envelope_shape(self) -> None:
        for envelope in ([], {"root": ROOT}):
            with self.subTest(envelope=envelope), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER.verify(envelope, "0" * 64)

    def test_verify_rejects_bad_root(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        for root in (
            "/etc/archiveweaver/x",
            "/etc/archiveweaver/a/b/c/",
            "/etc/archiveweaver/a/../c",
            "/var/lib/archiveweaver/a/b",
        ):
            with self.subTest(root=root), self.assertRaises(VERIFIER.InvalidBundle):
                VERIFIER.verify({**envelope, "root": root}, digest)

    def test_verify_rejects_bad_ancestry(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "ancestors": []}, digest)
        nondir = [dict(entry) for entry in envelope["ancestors"]]
        nondir[0]["isdir"] = False
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "ancestors": nondir}, digest)
        wrong = [dict(entry) for entry in envelope["ancestors"]]
        wrong[0]["path"] = "/wrong"
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "ancestors": wrong}, digest)

    def test_verify_rejects_bad_entry_lists(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "directories": "x"}, digest)
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "all_entries": [None] * (VERIFIER.MAX_ENTRIES + 1)}, digest)

    def test_verify_rejects_non_directory_entry(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        rogue = {"path": ROOT + "/file", "uid": 0, "gid": 0, "mode": "0644",
                 "isdir": False, "islnk": False}
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "directories": [*envelope["directories"], rogue]}, digest)

    def test_verify_rejects_duplicate_directory(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST,
            "base/kustomization.yaml": VALID_KUST,
        })
        duplicated = [*envelope["directories"], envelope["directories"][0]]
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "directories": duplicated}, digest)

    def test_verify_rejects_malformed_file_observation(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "files": [{"item": "nope"}]}, digest)

    def test_verify_rejects_non_regular_file_observation(self) -> None:
        for mutate in ({"encoding": "utf-8"}, {"isreg": None}):
            with self.subTest(mutate=mutate):
                envelope, digest = staged({"kustomization.yaml": VALID_KUST})
                row = envelope["files"][0]
                if "isreg" in mutate:
                    row["item"]["isreg"] = mutate["isreg"]
                else:
                    row["encoding"] = mutate["encoding"]
                with self.assertRaises(VERIFIER.InvalidBundle):
                    VERIFIER.verify(envelope, digest)

    def test_verify_rejects_hard_linked_file(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        envelope["files"][0]["item"]["nlink"] = 2
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_duplicate_file_path(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        envelope["files"].append(dict(envelope["files"][0]))
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_missing_file_content(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        del envelope["files"][0]["content"]
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_invalid_base64(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        envelope["files"][0]["content"] = "!!!not-base64!!!"
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_oversized_tree(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        with mock.patch.object(VERIFIER, "MAX_TREE_BYTES", 1), self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_changed_checksum(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        row = envelope["files"][0]
        original = base64.b64decode(row["content"])
        altered = bytes([original[0] ^ 0xFF]) + original[1:]
        row["content"] = base64.b64encode(altered).decode("ascii")
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_empty_tree(self) -> None:
        envelope, digest = staged({})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_malformed_all_entries(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        envelope["all_entries"].append("not-a-dict")
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_verify_rejects_file_became_non_file(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        entries = [dict(entry) for entry in envelope["all_entries"]]
        for entry in entries:
            if entry["path"].endswith("kustomization.yaml"):
                entry["isreg"] = False
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "all_entries": entries}, digest)

    def test_verify_rejects_directory_became_non_directory(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST,
            "base/kustomization.yaml": VALID_KUST,
        })
        entries = [dict(entry) for entry in envelope["all_entries"]]
        for entry in entries:
            if entry["path"] == ROOT + "/base":
                entry["isdir"] = False
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "all_entries": entries}, digest)

    def test_verify_rejects_incomplete_enumeration(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST,
            "base/kustomization.yaml": VALID_KUST,
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify({**envelope, "all_entries": envelope["all_entries"][:-1]}, digest)

    def test_verify_rejects_digest_mismatch(self) -> None:
        envelope, _ = staged({"kustomization.yaml": VALID_KUST})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, "0" * 64)

    def test_rejects_directory_without_kustomization(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"resources: [base]\n",
            "base/deployment.yaml": b"kind: Deployment\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_missing_directory_reference(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"resources: [missing]\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_component_reference_to_file(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"components: [base]\n",
            "base": b"kind: Deployment\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_recursive_directory_reference(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"resources: [base]\n",
            "base/kustomization.yaml": VALID_KUST + b"resources: [.]\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_allows_repeated_directory_reference(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"resources: [base, base]\n",
            "base/kustomization.yaml": VALID_KUST,
        })
        VERIFIER.verify(envelope, digest)

    def test_rejects_empty_kustomization_document(self) -> None:
        envelope, digest = staged({"kustomization.yaml": b""})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_invalid_yaml_kustomization(self) -> None:
        envelope, digest = staged({"kustomization.yaml": b"kind: [unclosed\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_unsupported_kind(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Other\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_allows_component_directory_reference(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"components: [comp]\n",
            "comp/kustomization.yaml": b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Component\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_rejects_missing_configuration_file(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"configurations: [missing.yaml]\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_non_list_patches(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"patches: {a: b}\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_allows_patch_strategic_merge_file(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"patchesStrategicMerge: [patch.yaml]\n",
            "patch.yaml": b"kind: Deployment\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_allows_patch_path_file(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"patches:\n  - path: patch.yaml\n",
            "patch.yaml": b"kind: Deployment\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_allows_inline_patch_entry(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"patches:\n  - patch: |\n      - op: add\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_allows_replacement_without_path(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"replacements:\n  - source:\n      kind: ConfigMap\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_rejects_patch_without_path_or_inline(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"patches:\n  - target:\n      kind: Deployment\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_invalid_patch_entry(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"patches: [123]\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_non_list_generator(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"configMapGenerator: {}\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_invalid_generator_entry(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"configMapGenerator: [1]\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_unsupported_generator_field(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"configMapGenerator:\n  - name: x\n    bogus: y\n",
        })
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_rejects_non_mapping_openapi(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST + b"openapi: []\n"})
        with self.assertRaises(VERIFIER.InvalidBundle):
            VERIFIER.verify(envelope, digest)

    def test_allows_openapi_path_file(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"openapi:\n  path: schema.yaml\n",
            "schema.yaml": b"{}\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_allows_openapi_without_path(self) -> None:
        envelope, digest = staged({
            "kustomization.yaml": VALID_KUST + b"openapi: {}\n",
        })
        VERIFIER.verify(envelope, digest)

    def test_main_usage_error(self) -> None:
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            self.assertEqual(VERIFIER.main(["prog"]), 2)
        self.assertIn("usage", stderr.getvalue())

    def test_main_rejects_empty_input(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b""))), \
                mock.patch("sys.stderr", stderr):
            self.assertEqual(VERIFIER.main(["prog", "0" * 64]), 2)
        self.assertIn("empty or too large", stderr.getvalue())

    def test_main_rejects_oversized_input(self) -> None:
        with mock.patch.object(VERIFIER, "MAX_INPUT_BYTES", 4), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"12345"))), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(VERIFIER.main(["prog", "0" * 64]), 2)

    def test_main_success(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        data = json.dumps(envelope).encode("utf-8")
        with mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))):
            self.assertEqual(VERIFIER.main(["prog", digest]), 0)

    def test_main_rejects_invalid_input(self) -> None:
        for payload in (
            b"not-json",
            b"\xff\xfe",
            b'{"a": 1, "a": 2}',
            json.dumps({"root": "x"}).encode("utf-8"),
        ):
            stderr = io.StringIO()
            with self.subTest(payload=payload), \
                    mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload))), \
                    mock.patch("sys.stderr", stderr):
                self.assertEqual(VERIFIER.main(["prog", "0" * 64]), 1)
            self.assertIn("rejected", stderr.getvalue())

    def test_main_guard_runs_via_runpy(self) -> None:
        envelope, digest = staged({"kustomization.yaml": VALID_KUST})
        data = json.dumps(envelope).encode("utf-8")
        with mock.patch.object(sys, "argv", [str(SCRIPT), digest]), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))), \
                mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 0)

    def test_module_without_yaml_fails_closed(self) -> None:
        spec = importlib.util.spec_from_file_location("verify_kustomize_bundle_no_yaml", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "yaml":
                raise ImportError("PyYAML unavailable")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            spec.loader.exec_module(module)
        self.assertIsNone(module.yaml)
        with self.assertRaises(module.InvalidBundle):
            module._check_closure({}, {})


if __name__ == "__main__":
    unittest.main()
