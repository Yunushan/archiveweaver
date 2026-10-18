from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-readiness-manifest.py"
SOURCE_COMMIT = "a" * 40
ANOTHER_COMMIT = "b" * 40


def load_module():
    spec = importlib.util.spec_from_file_location("verify_readiness_manifest", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


def write_manifest(directory: Path, document: bytes, name: str = "release-manifest.json") -> Path:
    manifest = directory / name
    manifest.write_bytes(document)
    return manifest


def document(source_revision: str) -> bytes:
    return json.dumps({"release": {"source_revision": source_revision}}).encode("utf-8")


class ReadinessManifestScriptTests(unittest.TestCase):
    def _run(self, arguments: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = MODULE.main(arguments)
        return code, stderr.getvalue()

    def test_usage_requires_three_arguments(self) -> None:
        code, stderr = self._run(["verify-readiness-manifest.py"])
        self.assertEqual(code, 2)
        self.assertIn("usage:", stderr)

    def test_rejects_malformed_expected_digest(self) -> None:
        code, stderr = self._run(["script", "manifest.json", "not-a-digest", SOURCE_COMMIT])
        self.assertEqual(code, 2)
        self.assertIn("SHA-256 hex digest", stderr)

    def test_rejects_malformed_source_commit(self) -> None:
        code, stderr = self._run(["script", "manifest.json", "0" * 64, "short"])
        self.assertEqual(code, 2)
        self.assertIn("full Git commit SHA", stderr)

    def test_missing_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code, stderr = self._run(["script", str(root / "absent.json"), "0" * 64, SOURCE_COMMIT])
        self.assertEqual(code, 1)
        self.assertIn("regular, non-symlink file", stderr)

    def test_symlinked_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write_manifest(root, document(SOURCE_COMMIT), "target.json")
            link = root / "linked.json"
            link.symlink_to(target)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(["script", str(link), hashlib.sha256(target.read_bytes()).hexdigest(), SOURCE_COMMIT])
        self.assertEqual(code, 1)

    def test_manifest_outside_the_repository_fails(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as elsewhere:
            payload = document(SOURCE_COMMIT)
            manifest = write_manifest(Path(elsewhere), payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", Path(repository)):
                code, stderr = self._run(
                    ["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT]
                )
        self.assertEqual(code, 1)
        self.assertIn("inside the signed repository checkout", stderr)

    def test_unreadable_manifest_fails_closed(self) -> None:
        def explode(*args, **kwargs):
            raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, document(SOURCE_COMMIT))
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                with mock.patch.object(MODULE, "_read_stable_bytes", explode):
                    code, stderr = self._run(["script", str(manifest), "0" * 64, SOURCE_COMMIT])
        self.assertEqual(code, 1)
        self.assertIn("inside the signed repository checkout", stderr)

    def test_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, document(SOURCE_COMMIT))
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code, stderr = self._run(["script", str(manifest), "0" * 64, SOURCE_COMMIT])
        self.assertEqual(code, 1)
        self.assertIn("controller-approved digest", stderr)

    def test_source_revision_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = document(ANOTHER_COMMIT)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code, stderr = self._run(
                    ["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT]
                )
        self.assertEqual(code, 1)
        self.assertIn("source revision does not match", stderr)

    def test_non_object_document_fails(self) -> None:
        payload = b'["not", "an", "object"]'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT])
        self.assertEqual(code, 1)

    def test_document_without_a_release_section_fails(self) -> None:
        payload = b'{"kind": "readiness"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT])
        self.assertEqual(code, 1)

    def test_invalid_json_fails(self) -> None:
        payload = b"{not json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT])
        self.assertEqual(code, 1)

    def test_invalid_utf8_fails(self) -> None:
        payload = b"\xff\xfe\x00"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT])
        self.assertEqual(code, 1)

    def test_matching_manifest_passes(self) -> None:
        payload = document(SOURCE_COMMIT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, payload)
            with mock.patch.object(MODULE, "REPOSITORY_ROOT", root):
                code = MODULE.main(
                    ["script", str(manifest), hashlib.sha256(payload).hexdigest(), SOURCE_COMMIT.upper()]
                )
        self.assertEqual(code, 0)

    def test_main_guard_exits_with_the_usage_code(self) -> None:
        with mock.patch.object(sys, "argv", ["verify-readiness-manifest.py"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
