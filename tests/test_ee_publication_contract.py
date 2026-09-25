from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from archiveweaver.readiness import _execution_environment_ok


ROOT = Path(__file__).resolve().parents[1]


class ExecutionEnvironmentPublicationContractTests(unittest.TestCase):
    def test_workflow_exports_the_actual_attestation_statement(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        exporter = next(
            step for step in workflow["jobs"]["package"]["steps"]
            if step.get("name") == "Export the signed controller-image provenance statement"
        )
        command = exporter["run"]
        self.assertTrue(command.startswith("python3 - <<'PY'\n"))
        script = command.removeprefix("python3 - <<'PY'\n").removesuffix("PY\n")
        digest = "sha256:" + "c" * 64
        image_name = "ghcr.io/example/archiveweaver-ee"
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": image_name, "digest": {"sha256": digest.removeprefix("sha256:")}}],
            "predicate": {},
        }
        statement_bytes = json.dumps(statement, separators=(",", ":")).encode()
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(statement_bytes).decode(),
                "signatures": [{"sig": "test signature"}],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_path = root / "attestation.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            environment = {
                **os.environ,
                "EE_ATTESTATION_BUNDLE": str(bundle_path),
                "IMAGE_NAME": image_name,
                "IMAGE_DIGEST": digest,
            }
            result = subprocess.run(
                [sys.executable, "-c", script], cwd=root, env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "archiveweaver-ee.provenance.json").read_bytes(), statement_bytes)
            self.assertEqual((root / "archiveweaver-ee.provenance.sigstore.json").read_bytes(), bundle_path.read_bytes())
            (root / "archiveweaver-ee.provenance.json").unlink()
            (root / "archiveweaver-ee.provenance.sigstore.json").unlink()
            statement["subject"][0]["digest"]["sha256"] = "0" * 64
            bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                json.dumps(statement).encode()
            ).decode()
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-c", script], cwd=root, env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "archiveweaver-ee.provenance.json").exists())

    def test_signed_publication_shape_matches_readiness_consumer(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        steps = workflow["jobs"]["package"]["steps"]
        producer = next(
            step for step in steps
            if step.get("name") == "Record the immutable controller-image publication"
        )
        attestor = next(
            step for step in steps
            if step.get("name") == "Attest controller-image build provenance"
        )
        exporter = next(
            step for step in steps
            if step.get("name") == "Export the signed controller-image provenance statement"
        )
        signer = next(
            step for step in steps
            if step.get("name") == "Sign and verify the immutable image publication record"
        )
        self.assertLess(steps.index(attestor), steps.index(exporter))
        self.assertLess(steps.index(exporter), steps.index(producer))
        self.assertLess(steps.index(producer), steps.index(signer))
        self.assertEqual(attestor["id"], "attest-ee")
        self.assertEqual(
            exporter["env"]["EE_ATTESTATION_BUNDLE"],
            "${{ steps.attest-ee.outputs.bundle-path }}",
        )
        for fragment in (
            'envelope.get("payload")',
            'base64.b64decode(encoded, validate=True)',
            '"name": os.environ["IMAGE_NAME"]',
            '"digest": {"sha256": image_digest.removeprefix("sha256:")}',
            'Path("archiveweaver-ee.provenance.json").write_bytes(statement_bytes)',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, exporter["run"])
        command = producer["run"]
        for fragment in (
            '--arg artifact_digest "${IMAGE_DIGEST}"',
            '--arg image "${IMAGE_REFERENCE}"',
            '--arg provenance_sha256 "${PROVENANCE_DIGEST}"',
            '--arg sbom_sha256 "${SBOM_DIGEST}"',
            'artifact_digest: $artifact_digest',
            'image: $image',
            'provenance_sha256: $provenance_sha256',
            'sbom_sha256: $sbom_sha256',
            'verifier: "cosign"',
            '.schema_version == 2',
            '.artifact_digest == env.IMAGE_DIGEST',
            '.image == env.IMAGE_REFERENCE',
            '.provenance_sha256 == env.PROVENANCE_DIGEST',
            '.sbom_sha256 == env.SBOM_DIGEST',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, command)
        self.assertIn('sha256sum archiveweaver-ee.spdx.json', command)
        self.assertIn('sha256sum archiveweaver-ee.provenance.json', command)
        self.assertIn(
            'archiveweaver-ee.publication.json.sigstore.json', signer["run"]
        )

        image_digest = "sha256:" + "c" * 64
        image_name = "ghcr.io/yunushan/archiveweaver/archiveweaver-ee"
        image = f"{image_name}@{image_digest}"
        sbom_bytes = b"indexed controller-image SBOM fixture\n"
        provenance_bytes = b"indexed controller-image provenance fixture\n"
        publication = {
            "schema_version": 2,
            "artifact_digest": image_digest,
            "base_image": "docker.io/library/python@sha256:" + "a" * 64,
            "image": image,
            "image_name": image_name,
            "immutable_reference": image,
            "local_image_id": "sha256:" + "b" * 64,
            "provenance_sha256": "sha256:" + hashlib.sha256(provenance_bytes).hexdigest(),
            "registry_digest": image_digest,
            "release_tag": "v0.1.0",
            "sbom_sha256": "sha256:" + hashlib.sha256(sbom_bytes).hexdigest(),
            "source_revision": "d" * 40,
            "verifier": "cosign",
        }
        self.assertEqual(
            set(publication),
            {
                "schema_version", "artifact_digest", "base_image", "image",
                "image_name", "immutable_reference", "local_image_id",
                "provenance_sha256", "registry_digest", "release_tag", "sbom_sha256",
                "source_revision", "verifier",
            },
        )
        publication_bytes = json.dumps(publication).encode("utf-8")
        value = {
            "name": "archiveweaver-ee",
            "image": image,
            "digest": image_digest,
            "provenance": "provenance.json",
            "provenance_verified": True,
            "sbom": "archiveweaver-ee.spdx.json",
            "signature": "archiveweaver-ee.publication.json.sigstore.json",
            "signature_verified": True,
            "signature_verification": {
                "evidence": "archiveweaver-ee.publication.json",
                "artifact_digest": image_digest,
                "image": image,
                "verifier": "cosign",
            },
        }
        manifest = {
            "release": {
                "version": "2026.09.1",
                "source_repository": "Yunushan/archiveweaver",
                "source_revision": "d" * 40,
            }
        }

        def indexed_bytes(candidate: Path | None, context: object) -> bytes | None:
            if candidate is None:
                return None
            if candidate.name == "archiveweaver-ee.publication.json":
                return publication_bytes
            if candidate.name == "archiveweaver-ee.spdx.json":
                return sbom_bytes
            if candidate.name == "provenance.json":
                return provenance_bytes
            return None

        with (
            mock.patch("archiveweaver.readiness._relative_candidate", side_effect=lambda value, root: root / value if isinstance(value, str) else None),
            mock.patch("archiveweaver.readiness._indexed_bytes", side_effect=indexed_bytes),
            mock.patch("archiveweaver.readiness._indexed_measure", return_value=(len(sbom_bytes), hashlib.sha256(sbom_bytes).hexdigest())),
            mock.patch("archiveweaver.readiness._provenance_payload", return_value={}),
            mock.patch("archiveweaver.readiness._provenance_binds_digests", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_binds_subjects", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_binds_source", return_value=True),
            mock.patch("archiveweaver.readiness._sbom_binds_name", return_value=True),
            mock.patch("archiveweaver.readiness._approved_signer", return_value=("identity", "issuer")),
            mock.patch("archiveweaver.readiness._evidence_exists", return_value=True),
            mock.patch("archiveweaver.readiness._evidence_metadata_matches", return_value=True) as metadata_matches,
            mock.patch("archiveweaver.readiness._sigstore_bundle_binds_content", return_value=True),
            mock.patch("archiveweaver.readiness._verify_sigstore_bundle", return_value=True) as verify,
        ):
            self.assertTrue(_execution_environment_ok(value, ROOT, None, manifest))
            self.assertEqual(verify.call_args.args[1], publication_bytes)
            provenance_bytes = b"hand-authored replacement provenance\n"
            self.assertFalse(_execution_environment_ok(value, ROOT, None, manifest))
            provenance_bytes = b"indexed controller-image provenance fixture\n"
            publication.pop("provenance_sha256")
            publication_bytes = json.dumps(publication).encode("utf-8")
            self.assertFalse(_execution_environment_ok(value, ROOT, None, manifest))
            publication["provenance_sha256"] = "sha256:" + hashlib.sha256(provenance_bytes).hexdigest()
            publication_bytes = json.dumps(publication).encode("utf-8")
            self.assertTrue(_execution_environment_ok(value, ROOT, None, manifest))
            publication["sbom_sha256"] = "sha256:" + "0" * 64
            publication_bytes = json.dumps(publication).encode("utf-8")
            self.assertFalse(_execution_environment_ok(value, ROOT, None, manifest))
            self.assertEqual(verify.call_count, 2)
            publication["sbom_sha256"] = "sha256:" + hashlib.sha256(sbom_bytes).hexdigest()
            publication_bytes = json.dumps(publication).encode("utf-8")
            metadata_matches.return_value = False
            self.assertFalse(_execution_environment_ok(value, ROOT, None, manifest))
            self.assertEqual(verify.call_count, 2)


if __name__ == "__main__":
    unittest.main()
