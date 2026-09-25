from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-provider-image-coverage.py"
SPEC = importlib.util.spec_from_file_location("verify_provider_image_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
coverage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage
SPEC.loader.exec_module(coverage)

PAPERLESS = "registry.example.org/docs/paperless@sha256:" + "a" * 64
POSTGRES = "registry.example.org/database/postgres@sha256:" + "b" * 64


def manifest(*refs: str) -> bytes:
    return json.dumps({
        "release": {
            "artifacts": [
                {"name": f"artifact-{i}", "image": ref, "digest": ref.split("@", 1)[1]}
                for i, ref in enumerate(refs)
            ]
        }
    }).encode()


def deployment(*containers: tuple[str, str]) -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "paperless", "namespace": "documents"},
        "spec": {"template": {"spec": {
            "containers": [{"name": name, "image": ref} for name, ref in containers],
        }}},
    }


class ProviderImageCoverageTests(unittest.TestCase):
    def test_image_reference_requires_explicit_registry_and_valid_port(self) -> None:
        self.assertTrue(coverage._immutable_image(PAPERLESS))
        self.assertTrue(coverage._immutable_image("localhost:5000/docs/app@sha256:" + "a" * 64))
        for ref in (
            "docs/app@sha256:" + "a" * 64,
            "registry/docs/app@sha256:" + "a" * 64,
            "registry:0/docs/app@sha256:" + "a" * 64,
            "registry:65536/docs/app@sha256:" + "a" * 64,
            "registry..example.org/docs/app@sha256:" + "a" * 64,
        ):
            with self.subTest(ref=ref):
                self.assertFalse(coverage._immutable_image(ref))

    def test_kubernetes_all_containers_and_init_containers_are_covered(self) -> None:
        resource = deployment(("web", PAPERLESS))
        resource["spec"]["template"]["spec"]["initContainers"] = [
            {"name": "migrate", "image": PAPERLESS},
            {"name": "database-check", "image": POSTGRES},
        ]
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "paperless"}}
        with patch.object(coverage, "_load_yaml", return_value=[resource, service]):
            coverage.verify(manifest(PAPERLESS, POSTGRES), "kubernetes", b"rendered")

    def test_kubernetes_rejects_unapproved_or_unused_release_images(self) -> None:
        resource = deployment(("web", PAPERLESS))
        with patch.object(coverage, "_load_yaml", return_value=[resource]):
            with self.assertRaisesRegex(coverage.CoverageFailure, "1 unapproved"):
                coverage.verify(manifest(POSTGRES), "kubernetes", b"rendered")
            with self.assertRaisesRegex(coverage.CoverageFailure, "1 unused"):
                coverage.verify(manifest(PAPERLESS, POSTGRES), "kubernetes", b"rendered")

    def test_kubernetes_rejects_unknown_resource_with_or_without_image_field(self) -> None:
        custom = {
            "apiVersion": "example.org/v1",
            "kind": "CreatesPods",
            "metadata": {"name": "hidden"},
            "spec": {},
        }
        for spec in ({}, {"template": {"image": POSTGRES}}):
            custom["spec"] = spec
            with self.subTest(spec=spec), patch.object(coverage, "_load_yaml", return_value=[deployment(("web", PAPERLESS)), custom]):
                with self.assertRaises(coverage.CoverageFailure):
                    coverage.verify(manifest(PAPERLESS), "kubernetes", b"rendered")

    def test_kubernetes_rejects_images_outside_known_container_fields(self) -> None:
        resource = deployment(("web", PAPERLESS))
        resource["spec"]["sidecar"] = {"image": POSTGRES}
        with patch.object(coverage, "_load_yaml", return_value=[resource]):
            with self.assertRaisesRegex(coverage.CoverageFailure, "outside its container lists"):
                coverage.verify(manifest(PAPERLESS, POSTGRES), "kubernetes", b"rendered")

    def test_kubernetes_rejects_missing_or_mutable_container_images(self) -> None:
        for ref in (None, "paperless:latest", "paperless:5000@sha256:" + "a" * 64):
            resource = deployment(("web", ref))
            with self.subTest(ref=ref), patch.object(coverage, "_load_yaml", return_value=[resource]):
                with self.assertRaisesRegex(coverage.CoverageFailure, "missing or mutable image"):
                    coverage.verify(manifest(PAPERLESS), "kubernetes", b"rendered")

    def test_kubernetes_rejects_duplicate_resource_and_container_names(self) -> None:
        resource = deployment(("web", PAPERLESS))
        with patch.object(coverage, "_load_yaml", return_value=[resource, resource]):
            with self.assertRaisesRegex(coverage.InvalidInput, "duplicate resources"):
                coverage.verify(manifest(PAPERLESS), "kubernetes", b"rendered")
        duplicate_containers = deployment(("web", PAPERLESS), ("web", POSTGRES))
        with patch.object(coverage, "_load_yaml", return_value=[duplicate_containers]):
            with self.assertRaisesRegex(coverage.CoverageFailure, "duplicate container name"):
                coverage.verify(manifest(PAPERLESS, POSTGRES), "kubernetes", b"rendered")

    def test_compose_accepts_exact_services_and_reused_image(self) -> None:
        model = {"services": {"web": {"image": PAPERLESS}, "worker": {"image": PAPERLESS}}}
        with patch.object(coverage, "_load_yaml", return_value=[model]):
            coverage.verify(manifest(PAPERLESS), "docker", b"rendered")
            coverage.verify(manifest(PAPERLESS), "docker-swarm", b"rendered")

    def test_compose_rejects_build_capable_or_unresolved_directives(self) -> None:
        for directive in ({"build": "."}, {"develop": {"watch": []}}, {"extends": "base"}, {"pull_policy": "build"}):
            model = {"services": {"web": {"image": PAPERLESS, **directive}}}
            with self.subTest(directive=directive), patch.object(coverage, "_load_yaml", return_value=[model]):
                with self.assertRaises(coverage.CoverageFailure):
                    coverage.verify(manifest(PAPERLESS), "docker", b"rendered")

    def test_compose_rejects_hidden_image_and_unsupported_top_level_directive(self) -> None:
        for extra in ({"x-hidden": {"image": POSTGRES}}, {"include": ["other.yml"]}):
            model = {"services": {"web": {"image": PAPERLESS}}, **extra}
            with self.subTest(extra=extra), patch.object(coverage, "_load_yaml", return_value=[model]):
                with self.assertRaises(coverage.CoverageFailure):
                    coverage.verify(manifest(PAPERLESS), "docker-swarm", b"rendered")

    def test_manifest_rejects_duplicate_image_rows_and_digest_mismatch(self) -> None:
        with self.assertRaisesRegex(coverage.CoverageFailure, "duplicate OCI image"):
            coverage._manifest_images(manifest(PAPERLESS, PAPERLESS))
        wrong_digest = json.loads(manifest(PAPERLESS))
        wrong_digest["release"]["artifacts"][0]["digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(coverage.CoverageFailure, "digests differ"):
            coverage._manifest_images(json.dumps(wrong_digest).encode())

    def test_manifest_rejects_present_empty_image_and_duplicate_json_keys(self) -> None:
        invalid = b'{"release":{"artifacts":[{"image":null,"digest":"sha256:abc"}]}}'
        with self.assertRaises(coverage.CoverageFailure):
            coverage._manifest_images(invalid)
        with self.assertRaisesRegex(coverage.InvalidInput, "duplicate JSON keys"):
            coverage._manifest_images(b'{"release":{},"release":{}}')

    def test_manifest_rejects_nonfinite_and_unbounded_json_numbers(self) -> None:
        for number in (b"NaN", b"Infinity", b"-Infinity", b"1e9999"):
            raw = b'{"release":{"artifacts":[],"untrusted":' + number + b'}}'
            with self.subTest(number=number), self.assertRaisesRegex(
                coverage.InvalidInput, "finite, bounded UTF-8 JSON"
            ):
                coverage._manifest_images(raw)

    def test_manifest_can_include_unrelated_package_artifacts(self) -> None:
        mixed = json.loads(manifest(PAPERLESS))
        mixed["release"]["artifacts"].append({"name": "package", "digest": "sha256:" + "c" * 64})
        self.assertEqual(coverage._manifest_images(json.dumps(mixed).encode()), {PAPERLESS})

    def test_manifest_read_is_stable_and_bound_to_protected_digest(self) -> None:
        raw = Path(__file__).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(coverage._read_manifest(str(Path(__file__).resolve()), digest), raw)
        with self.assertRaisesRegex(coverage.CoverageFailure, "protected SHA-256"):
            coverage._read_manifest(str(Path(__file__).resolve()), "0" * 64)
        with self.assertRaisesRegex(coverage.InvalidInput, "64 lowercase hex"):
            coverage._read_manifest(str(Path(__file__).resolve()), "not-a-digest")

    def test_cli_returns_distinct_coverage_and_input_exit_codes(self) -> None:
        args = [str(SCRIPT), str(Path(__file__).resolve()), "docker", "a" * 64]
        model = {"services": {"web": {"image": PAPERLESS}}}
        fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(b"rendered"))
        with patch.object(coverage, "_read_manifest", return_value=manifest(PAPERLESS)), patch.object(coverage, "_load_yaml", return_value=[model]), patch.object(coverage.sys, "stdin", fake_stdin):
            self.assertEqual(coverage.main(args), 0)
        fake_stdin.buffer.seek(0)
        with patch.object(coverage, "_read_manifest", return_value=manifest(POSTGRES)), patch.object(coverage, "_load_yaml", return_value=[model]), patch.object(coverage.sys, "stdin", fake_stdin), patch.object(coverage.sys, "stderr", io.StringIO()):
            self.assertEqual(coverage.main(args), 1)
        with patch.object(coverage.sys, "stderr", io.StringIO()):
            self.assertEqual(coverage.main(args[:-1]), 2)

    @unittest.skipIf(coverage.yaml is None, "PyYAML is unavailable")
    def test_strict_yaml_rejects_duplicate_keys_and_aliases(self) -> None:
        for raw in (
            b"services:\n  web:\n    image: one\n    image: two\n",
            b"services:\n  web: &web\n    image: one\n  worker: *web\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(coverage.InvalidInput):
                coverage._load_yaml(raw)

    @unittest.skipIf(coverage.yaml is None, "PyYAML is unavailable")
    def test_strict_yaml_stops_at_document_limit(self) -> None:
        raw = b"kind: Service\n---\n" * (coverage.MAX_DOCUMENTS + 1)
        with self.assertRaisesRegex(coverage.InvalidInput, "document limit"):
            coverage._load_yaml(raw)

    @unittest.skipIf(coverage.yaml is None, "PyYAML is unavailable")
    def test_strict_yaml_parses_actual_kustomize_and_compose_shapes(self) -> None:
        kube = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: paperless
spec:
  template:
    spec:
      containers:
        - name: web
          image: {PAPERLESS}
---
apiVersion: v1
kind: Service
metadata:
  name: paperless
""".encode()
        coverage.verify(manifest(PAPERLESS), "kubernetes", kube)
        compose = f"services:\n  web:\n    image: {PAPERLESS}\n".encode()
        coverage.verify(manifest(PAPERLESS), "docker", compose)


if __name__ == "__main__":
    unittest.main()
