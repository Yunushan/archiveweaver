from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
