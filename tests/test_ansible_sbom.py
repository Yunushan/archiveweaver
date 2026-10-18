from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/generate-ansible-sbom.py"))
atomic_write = MODULE["atomic_write"]
build_document = MODULE["build_document"]
generate = MODULE["generate"]
parse_lock = MODULE["parse_lock"]
project_version = MODULE["project_version"]
render_document = MODULE["render_document"]
source_epoch = MODULE["source_epoch"]


class AnsibleSbomTests(unittest.TestCase):
    def test_repository_sbom_is_complete_and_deterministic(self) -> None:
        lock_path = ROOT / "deploy/ansible/requirements.txt"
        lock_bytes = lock_path.read_bytes()
        packages = parse_lock(lock_bytes.decode("utf-8"))
        version = project_version((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        first = build_document(lock_bytes, packages, version, 1_700_000_000)
        second = build_document(lock_bytes, packages, version, 1_700_000_000)
        self.assertEqual(render_document(first), render_document(second))
        self.assertEqual(len(packages), 36)
        self.assertIn("ansible-runner", {package.name for package in packages})
        self.assertEqual(first["spdxVersion"], "SPDX-2.3")
        self.assertEqual(first["dataLicense"], "CC0-1.0")
        self.assertEqual(
            first["creationInfo"]["created"],  # type: ignore[index]
            "2023-11-14T22:13:20Z",
        )
        self.assertRegex(
            first["documentNamespace"],
            r"^https://github\.com/Yunushan/archiveweaver/spdx/"
            r"ansible-controller/[0-9a-f]{64}$",
        )

        package_records = {
            item["name"]: item for item in first["packages"]  # type: ignore[index]
        }
        self.assertEqual(len(package_records), 37)
        self.assertIn("archiveweaver-ansible-controller", package_records)
        for package in packages:
            record = package_records[package.name]
            self.assertEqual(record["versionInfo"], package.version)
            self.assertEqual(
                {
                    annotation["comment"].removeprefix(
                        "archiveweaver:approved-wheel-sha256:"
                    )
                    for annotation in record["annotations"]
                },
                set(package.hashes),
            )
            self.assertEqual(
                record["externalRefs"][0]["referenceLocator"],
                f"pkg:pypi/{package.name}@{package.version}",
            )

        lock_record = first["files"][0]  # type: ignore[index]
        self.assertEqual(lock_record["fileName"], "deploy/ansible/requirements.txt")
        self.assertEqual(
            lock_record["checksums"],
            [
                {
                    "algorithm": "SHA1",
                    "checksumValue": hashlib.sha1(
                        lock_bytes, usedforsecurity=False
                    ).hexdigest(),
                },
                {
                    "algorithm": "SHA256",
                    "checksumValue": hashlib.sha256(lock_bytes).hexdigest(),
                }
            ],
        )
        relationships = first["relationships"]
        self.assertEqual(len(relationships), 37)  # type: ignore[arg-type]
        self.assertEqual(
            sum(
                relationship["relationshipType"] == "DEPENDS_ON"
                for relationship in relationships  # type: ignore[union-attr]
            ),
            36,
        )

    def test_document_namespace_changes_with_identity_inputs(self) -> None:
        packages = parse_lock(
            "example==1.0 \\\n"
            "    --hash=sha256:" + "a" * 64 + "\n"
        )
        one = build_document(b"one", packages, "1.0", 1)
        changed_lock = build_document(b"two", packages, "1.0", 1)
        changed_version = build_document(b"one", packages, "2.0", 1)
        changed_epoch = build_document(b"one", packages, "1.0", 2)
        namespaces = {
            document["documentNamespace"]
            for document in (one, changed_lock, changed_version, changed_epoch)
        }
        self.assertEqual(len(namespaces), 4)

    def test_lock_parser_rejects_ambiguous_or_unverified_content(self) -> None:
        digest = "a" * 64
        invalid_inputs = (
            "",
            "example==1.0 \\\n",
            f"    --hash=sha256:{digest}\n",
            "--index-url=https://example.invalid/simple\n",
            (
                f"example==1.0 \\\n    --hash=sha256:{digest}\n"
                f"example==2.0 \\\n    --hash=sha256:{'b' * 64}\n"
            ),
            (
                f"example==1.0 \\\n    --hash=sha256:{digest} \\\n"
                f"    --hash=sha256:{digest}\n"
            ),
        )
        for content in invalid_inputs:
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                parse_lock(content)

    def test_project_version_and_source_epoch_are_fail_closed(self) -> None:
        self.assertEqual(
            project_version('[build-system]\nversion = "wrong"\n[project]\nversion = "1.2.3"\n'),
            "1.2.3",
        )
        for content in ("", "[project]\n", '[project]\nversion = "1"\nversion = "2"\n'):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                project_version(content)

        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                source_epoch(None)
        for value in ("-1", "1.5", "not-a-date", "１２"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                source_epoch(value)
        self.assertEqual(source_epoch("0"), 0)

    def test_cli_generates_and_checks_reproducible_output(self) -> None:
        script = ROOT / "scripts/generate-ansible-sbom.py"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "controller.spdx.json"
            command = [
                sys.executable,
                str(script),
                "--source-date-epoch",
                "1700000000",
                "--output",
                str(output),
            ]
            generated = subprocess.run(
                command,
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            first = output.read_bytes()
            json.loads(first)

            checked = subprocess.run(
                [*command, "--check"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(output.read_bytes(), first)

            output.write_text("{}\n", encoding="utf-8")
            stale = subprocess.run(
                [*command, "--check"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(stale.returncode, 1)
            self.assertIn("stale or non-reproducible", stale.stderr)

    def test_atomic_writer_refuses_symlink_output_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_bytes(b"original")
            link = root / "output.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("file symlink creation is unavailable")
            with self.assertRaises(RuntimeError):
                atomic_write(link, b"replacement")
            self.assertEqual(target.read_bytes(), b"original")

    def test_regular_file_reader_rejects_missing_and_symlinked_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(RuntimeError):
                MODULE["read_regular_file"](root / "missing.txt", "input")
            real = root / "real.txt"
            real.write_bytes(b"payload")
            self.assertEqual(
                MODULE["read_regular_file"](real, "input"),
                b"payload",
            )
            link = root / "link.txt"
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest("file symlink creation is unavailable")
            with self.assertRaises(RuntimeError):
                MODULE["read_regular_file"](link, "input")

    def test_source_epoch_rejects_out_of_range_timestamp(self) -> None:
        with self.assertRaises(RuntimeError):
            source_epoch(str(10**20))

    def test_spdx_identifier_rejects_unrepresentable_names(self) -> None:
        with self.assertRaises(RuntimeError):
            MODULE["spdx_id"]("-._-")

    def test_atomic_writer_creates_and_replaces_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "nested" / "output.json"
            atomic_write(target, b"first")
            self.assertEqual(target.read_bytes(), b"first")
            atomic_write(target, b"second")
            self.assertEqual(target.read_bytes(), b"second")

    def test_atomic_writer_rejects_directory_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "output"
            directory.mkdir()
            with self.assertRaises(RuntimeError):
                atomic_write(directory, b"content")

    def test_atomic_writer_propagates_creation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "output.json"
            with mock.patch.object(
                MODULE["tempfile"],
                "NamedTemporaryFile",
                side_effect=OSError("boom"),
            ), self.assertRaises(OSError):
                atomic_write(target, b"content")
            self.assertFalse(target.exists())

    def test_atomic_writer_skips_cleanup_without_named_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "output.json"
            handler = mock.Mock()
            handler.name = None
            handler.fileno.return_value = 0
            script_globals = atomic_write.__globals__
            original_path = script_globals["Path"]
            fake_path = mock.Mock()
            script_globals["Path"] = fake_path
            try:
                with (
                    mock.patch.object(
                        MODULE["tempfile"],
                        "NamedTemporaryFile",
                        return_value=contextlib.nullcontext(handler),
                    ),
                    mock.patch.object(MODULE["os"], "fsync"),
                ):
                    atomic_write(target, b"content")
            finally:
                script_globals["Path"] = original_path
            handler.write.assert_called_once_with(b"content")
            fake_path.assert_called_once_with(None)

    def test_generate_reads_repository_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "requirements.txt"
            lock.write_text(
                "example==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            project = root / "pyproject.toml"
            project.write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
            rendered, package_count, artifact_count = generate(lock, project, 0)
            self.assertEqual(package_count, 1)
            self.assertEqual(artifact_count, 1)
            self.assertEqual(
                json.loads(rendered)["name"],
                "archiveweaver-ansible-controller-9.9.9",
            )

    def test_generate_rejects_non_utf8_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "requirements.txt"
            lock.write_text(
                "example==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            project = root / "pyproject.toml"
            project.write_text('[project]\nversion = "1"\n', encoding="utf-8")
            bad = root / "bad.txt"
            bad.write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(RuntimeError, "valid UTF-8"):
                generate(bad, project, 0)
            with self.assertRaisesRegex(RuntimeError, "valid UTF-8"):
                generate(lock, bad, 0)

    def test_main_generates_checks_and_reports_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "requirements.txt"
            lock.write_text(
                "example==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            project = root / "pyproject.toml"
            project.write_text('[project]\nversion = "1"\n', encoding="utf-8")
            output = root / "output.json"
            base = [
                "generate-ansible-sbom.py",
                "--lock",
                str(lock),
                "--project",
                str(project),
                "--output",
                str(output),
                "--source-date-epoch",
                "0",
            ]
            with mock.patch.object(sys, "argv", base):
                self.assertEqual(MODULE["main"](), 0)
            self.assertTrue(output.is_file())

            with mock.patch.object(sys, "argv", [*base, "--check"]):
                self.assertEqual(MODULE["main"](), 0)

            output.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(sys, "argv", [*base, "--check"]):
                self.assertEqual(MODULE["main"](), 1)

            stderr = io.StringIO()
            missing = [
                "generate-ansible-sbom.py",
                "--lock",
                str(root / "missing.txt"),
                "--project",
                str(project),
                "--output",
                str(output),
                "--source-date-epoch",
                "0",
            ]
            with (
                mock.patch.object(sys, "argv", missing),
                redirect_stderr(stderr),
            ):
                self.assertEqual(MODULE["main"](), 1)
            self.assertIn("Ansible SBOM error", stderr.getvalue())

    def test_module_entrypoint_runs_main_under_main_guard(self) -> None:
        script = ROOT / "scripts/generate-ansible-sbom.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "requirements.txt"
            lock.write_text(
                "example==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            project = root / "pyproject.toml"
            project.write_text('[project]\nversion = "1"\n', encoding="utf-8")
            argv = [
                str(script),
                "--lock",
                str(lock),
                "--project",
                str(project),
                "--output",
                str(root / "output.json"),
                "--source-date-epoch",
                "0",
            ]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(script), run_name="__main__")
            self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
