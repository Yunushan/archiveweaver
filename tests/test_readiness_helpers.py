from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from archiveweaver.catalog import Catalog
from archiveweaver.evidence import build_evidence_index
from archiveweaver.readiness import (
    GITHUB_AUDIT_API_VERSION,
    GITHUB_AUDIT_CONTROL_NAMES,
    _all_pass_with_evidence,
    _approved_signer,
    _approval_window_errors,
    _artifact_core_proof_paths,
    _artifact_proof_paths,
    _attestation_subject_bindings,
    _attestation_subject_digests,
    _claim_evidence_ok,
    _controller_pinned_file,
    _cyclonedx_sbom_valid,
    _digest_matches,
    _decoded_base64,
    _evidence_context,
    _evidence_index_errors,
    _evidence_max_age,
    _evidence_metadata_errors,
    _evidence_metadata_matches,
    _evidence_payload_matches,
    _evidence_record_exists,
    _evidence_timestamp_is_fresh,
    _execution_environment_ok,
    _execution_environment_core_proof_paths,
    _execution_environment_proof_paths,
    _freshness_window_label,
    _github_controls_errors,
    _github_controls_proof_paths,
    _github_release_certificate_identity,
    _indexed_bytes,
    _indexed_dsse_statement_ok,
    _indexed_measure,
    _image_provenance_ok,
    _is_absolute_uri,
    _is_current_or_past_timestamp,
    _json_evidence_payload,
    _json_shape_errors,
    _oci_descriptor_ok,
    _oci_image_manifest_ok,
    _oci_release_image_ref_ok,
    _parse_timestamp,
    _product_ok,
    _provenance_binds_digests,
    _provenance_binds_source,
    _provenance_binds_subjects,
    _provenance_payload,
    _relative_candidate,
    _release_ok,
    _release_provenance_signature_ok,
    _release_proof_names,
    _release_proof_paths,
    _sbom_binds_name,
    _sbom_binds_named_sha256,
    _sbom_payload,
    _sigstore_bundle_binds_content,
    _sigstore_bundle_binds_digest,
    _signing_policy,
    _signed_artifact_ok,
    _spdx_packages,
    _structured_json_payload,
    _trusted_file_bytes,
    _verify_sigstore_bundle,
    assess_readiness,
    validate_manifest,
)


def _context(
    root: Path,
    paths: set[str] | dict[str, object],
    catalog: Catalog,
) -> tuple[Path, dict[str, tuple[int, str]], Catalog]:
    entries: dict[str, tuple[int, str]] = {}
    for relative in paths:
        content = (root / relative).read_bytes()
        entries[relative] = (len(content), hashlib.sha256(content).hexdigest())
    return root, entries, catalog


class ReadinessHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_scored_evidence_requires_claim_source_and_passing_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "name": "restore",
                "status": "pass",
                "evidence": "restore.json",
                "solution": "paperless-ngx",
                "runtime": "rke2",
                "os_id": "ubuntu-24.04",
                "release": "2026.09.1",
                "environment": "production",
                "execution_environment": "restore",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "operator": "operations",
                "fixture_set": "restore-drill-1",
            }
            revision = "a" * 40
            manifest = {
                "service": {
                    "solution_id": "paperless-ngx",
                    "runtime": "rke2",
                    "os_id": "ubuntu-24.04",
                    "environment": "production",
                },
                "release": {"version": "2026.09.1", "source_revision": revision},
            }
            payload = {
                **record,
                "claim": "data_protection.restore_test",
                "source_revision": revision,
                "outcome": {
                    "status": "pass",
                    "method": "automated",
                    "summary": "Production restore completed and verified",
                    "source": "urn:archiveweaver:ansible:restore",
                },
                "returncode": 0,
            }

            def accepted(proof: dict[str, object], claim: str = "data_protection.restore_test") -> bool:
                (root / "restore.json").write_text(json.dumps(proof), encoding="utf-8")
                return _evidence_record_exists(
                    record,
                    root,
                    _context(root, {"restore.json"}, self.catalog),
                    manifest,
                    freshness_policy=claim,
                )

            self.assertTrue(accepted(payload))
            without_execution_environment = dict(record)
            without_execution_environment.pop("execution_environment")
            self.assertFalse(
                _evidence_record_exists(
                    without_execution_environment,
                    root,
                    _context(root, {"restore.json"}, self.catalog),
                    manifest,
                    freshness_policy="data_protection.restore_test",
                )
            )
            self.assertFalse(accepted(payload, "data_protection.fixity_test"))
            for changes in (
                {"claim": "data_protection.fixity_test"},
                {"source_revision": "b" * 40},
                {"source_revision": None},
                {"outcome": None},
                {"outcome": {**payload["outcome"], "status": "fail"}},
                {"outcome": {**payload["outcome"], "method": []}},
                {"outcome": {**payload["outcome"], "summary": ""}},
                {"returncode": 1},
                {"returncode": True},
                {"restore_returncode": 1},
                {"outcome": {**payload["outcome"], "returncode": 2}},
                {"check": {"returncode": 1}},
                {"outcome": {**payload["outcome"], "checks": [{"rc": 1}]}},
            ):
                with self.subTest(changes=changes):
                    self.assertFalse(accepted({**payload, **changes}))
            manual = {
                **payload,
                "outcome": {
                    "status": "pass",
                    "method": "manual",
                    "summary": "Restore artifacts inspected against the source bundle",
                    "source": "https://tickets.example.org/CHG-1234",
                    "reviewed_by": "independent-reviewer@example.org",
                },
            }
            self.assertTrue(accepted(manual))
            self.assertFalse(
                accepted({**manual, "outcome": {**manual["outcome"], "reviewed_by": ""}})
            )
            self.assertFalse(
                accepted({**manual, "outcome": {**manual["outcome"], "reviewed_by": "operations"}})
            )
            self.assertFalse(
                accepted({**manual, "outcome": {**manual["outcome"], "reviewed_by": " Operations "}})
            )

            named_record = {**record, "name": "smoke"}
            named_payload = {
                **payload,
                "name": "smoke",
                "claim": "product_certification.test_matrix.smoke",
            }
            (root / "restore.json").write_text(json.dumps(named_payload), encoding="utf-8")
            named_context = _context(root, {"restore.json"}, self.catalog)
            self.assertTrue(
                _all_pass_with_evidence(
                    [named_record], root, named_context, {"smoke"}, manifest,
                    freshness_policy="product_certification.test_matrix",
                )
            )
            named_payload["claim"] = "product_certification.test_matrix.migration"
            (root / "restore.json").write_text(json.dumps(named_payload), encoding="utf-8")
            self.assertFalse(
                _all_pass_with_evidence(
                    [named_record], root,
                    _context(root, {"restore.json"}, self.catalog),
                    {"smoke"}, manifest,
                    freshness_policy="product_certification.test_matrix",
                )
            )

    def test_json_shape_uri_timestamp_and_freshness_guards(self) -> None:
        self.assertIn(
            "node safety limit",
            _json_shape_errors([1, 2], "document", max_nodes=1)[0],
        )
        nested: object = "leaf"
        for _ in range(200):
            nested = [nested]
        self.assertIn(
            "nesting limit",
            _json_shape_errors(nested, "document", max_nodes=1_000)[0],
        )

        self.assertFalse(_is_absolute_uri(None))
        self.assertFalse(_is_absolute_uri("https://["))
        self.assertIsNone(_parse_timestamp("2026-02-30T12:00:00Z"))
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(
            _is_current_or_past_timestamp("2026-09-11T11:00:00Z", now=now)
        )
        self.assertFalse(
            _is_current_or_past_timestamp("2026-09-12T12:00:00Z", now=now)
        )
        self.assertFalse(_is_current_or_past_timestamp("invalid", now=now))

        default_backup_age = _evidence_max_age(
            "data_protection.backup",
            {"data_protection": {"rpo_minutes": "60"}},
        )
        self.assertIsNotNone(default_backup_age)
        self.assertEqual(_freshness_window_label(timedelta(seconds=61)), "61 seconds")

    def test_filesystem_and_index_measurement_failures_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "proof.json"
            proof.write_text('{"status":"pass"}\n', encoding="utf-8")
            measured = (proof.stat().st_size, hashlib.sha256(proof.read_bytes()).hexdigest())
            context = (root, {"proof.json": measured}, self.catalog)

            with (
                mock.patch(
                    "archiveweaver.readiness.has_symlink_component",
                    return_value=False,
                ),
                mock.patch.object(Path, "resolve", side_effect=OSError("denied")),
            ):
                self.assertIsNone(_relative_candidate("proof.json", root))

            path_type = type(proof.resolve())
            with (
                mock.patch(
                    "archiveweaver.readiness.has_symlink_component",
                    return_value=False,
                ),
                mock.patch.object(
                    path_type,
                    "resolve",
                    autospec=True,
                    side_effect=lambda candidate: candidate,
                ),
                mock.patch.object(path_type, "is_symlink", return_value=False),
                mock.patch.object(path_type, "is_file", return_value=True),
                mock.patch.object(
                    path_type, "stat", side_effect=OSError("raced")
                ) as stat,
            ):
                self.assertIsNone(_relative_candidate("proof.json", root))
                self.assertTrue(stat.called)

            self.assertIsNone(_indexed_measure(root.parent / "outside.json", context))
            self.assertIsNone(_indexed_measure(proof, (root, {}, self.catalog)))
            with mock.patch(
                "archiveweaver.readiness._measure_regular_file",
                side_effect=OSError("raced"),
            ):
                self.assertIsNone(_indexed_measure(proof, context))

            self.assertIsNone(_indexed_bytes(root.parent / "outside.json", context))
            oversized = (root, {"proof.json": (100_000_000, measured[1])}, self.catalog)
            self.assertIsNone(_indexed_bytes(proof, oversized))
            with mock.patch(
                "archiveweaver.readiness._read_stable_bytes",
                side_effect=OSError("raced"),
            ):
                self.assertIsNone(_indexed_bytes(proof, context))

    def test_structured_evidence_rejects_invalid_bytes_depth_and_missing_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unindexed = root / "unindexed.json"
            unindexed.write_text('{"items":[{"name":"proof"}]}', encoding="utf-8")
            invalid = root / "invalid.json"
            invalid.write_bytes(b"{\xff")
            valid = root / "valid.json"
            valid.write_text('{"items":[{"name":"proof"}]}', encoding="utf-8")
            context = _context(root, {"invalid.json", "valid.json"}, self.catalog)

            self.assertIsNone(
                _structured_json_payload(
                    "unindexed.json", root, context, (("items",),)
                )
            )
            self.assertIsNone(
                _structured_json_payload("invalid.json", root, context, (("items",),))
            )
            self.assertIsNone(
                _json_evidence_payload(
                    {"evidence": "invalid.json"}, root, context
                )
            )
            with mock.patch(
                "archiveweaver.readiness._json_shape_errors",
                return_value=["too deep"],
            ):
                self.assertIsNone(
                    _structured_json_payload(
                        "valid.json", root, context, (("items",),)
                    )
                )

            self.assertEqual(_artifact_core_proof_paths(None), set())
            self.assertEqual(_execution_environment_core_proof_paths(None), set())
            self.assertEqual(_release_proof_names(None), set())
            self.assertEqual(
                _release_proof_names(
                    {
                        "artifacts": [
                            {"name": "Product"},
                            {"name": "latest"},
                            "invalid",
                        ]
                    }
                ),
                {"product"},
            )
            self.assertEqual(
                _github_controls_proof_paths(
                    {
                        "path": "controls.json",
                        "signature": "controls.sigstore.json",
                        "signature_verification": {"evidence": "verify.json"},
                    }
                ),
                {"controls.json", "controls.sigstore.json", "verify.json"},
            )

    def test_sigstore_bundle_must_bind_the_indexed_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signed_content = b"hosted production controls\n"
            bundle_path = root / "controls.json.sigstore.json"
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(b"certificate").decode()
                    },
                    "tlogEntries": [
                        {
                            "canonicalizedBody": base64.b64encode(
                                b"transparency entry"
                            ).decode()
                        }
                    ],
                },
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(
                            hashlib.sha256(signed_content).digest()
                        ).decode(),
                    },
                    "signature": base64.b64encode(b"signature").decode(),
                },
            }

            def check(candidate: dict[str, object]) -> bool:
                bundle_path.write_text(json.dumps(candidate), encoding="utf-8")
                return _sigstore_bundle_binds_content(
                    bundle_path.name,
                    signed_content,
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )

            self.assertTrue(check(bundle))
            for mutation in (
                {"mediaType": "application/vnd.dev.sigstore.bundle.v0.2+json"},
                {"verificationMaterial": []},
                {"verificationMaterial": {"certificate": {"rawBytes": "%%%"}}},
                {
                    "verificationMaterial": {
                        "certificate": {
                            "rawBytes": base64.b64encode(b"certificate").decode()
                        }
                    }
                },
                {
                    "verificationMaterial": {
                        "certificate": {
                            "rawBytes": base64.b64encode(b"certificate").decode()
                        },
                        "tlogEntries": [{"canonicalizedBody": "%%%"}],
                    }
                },
                {"messageSignature": []},
                {
                    "messageSignature": {
                        "messageDigest": {
                            "algorithm": "SHA2_256",
                            "digest": base64.b64encode(b"wrong digest").decode(),
                        },
                        "signature": base64.b64encode(b"signature").decode(),
                    }
                },
            ):
                with self.subTest(mutation=mutation):
                    candidate = copy.deepcopy(bundle)
                    candidate.update(mutation)
                    self.assertFalse(check(candidate))

            self.assertIsNone(_decoded_base64(None))
            self.assertFalse(
                _sigstore_bundle_binds_content(
                    bundle_path.name,
                    signed_content,
                    root,
                    (root, {}, self.catalog),
                )
            )
            bundle_path.write_bytes(b"{\xff")
            self.assertFalse(
                _sigstore_bundle_binds_content(
                    bundle_path.name,
                    signed_content,
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )
            )

            bundle_path.write_text("{}\n", encoding="utf-8")
            self.assertFalse(
                _sigstore_bundle_binds_content(
                    bundle_path.name,
                    signed_content,
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )
            )

            bundle_path.write_text("{}\n", encoding="utf-8")
            self.assertFalse(
                _sigstore_bundle_binds_content(
                    "controls.bundle.json",
                    signed_content,
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )
            )

            self.assertFalse(
                _sigstore_bundle_binds_digest(
                    bundle_path.name,
                    "sha256:malformed",
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )
            )

    def test_controller_trust_files_reject_relative_missing_and_raced_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted_file = root / "approved-root.json"
            trusted_bytes = b"controller-approved trusted root"
            trusted_file.write_bytes(trusted_bytes)
            path_variable = "ARCHIVEWEAVER_TEST_TRUST_PATH"
            digest_variable = "ARCHIVEWEAVER_TEST_TRUST_SHA256"
            digest = hashlib.sha256(trusted_bytes).hexdigest()
            environment = {
                path_variable: str(trusted_file),
                digest_variable: digest,
            }
            with mock.patch.dict("os.environ", environment):
                self.assertEqual(
                    _controller_pinned_file(
                        path_variable, digest_variable, 1024, "trusted root"
                    ),
                    trusted_file,
                )
                self.assertEqual(
                    _trusted_file_bytes(
                        path_variable, digest_variable, 1024, "trusted root"
                    ),
                    trusted_bytes,
                )

                with mock.patch.dict("os.environ", {path_variable: "approved-root.json"}):
                    self.assertIsNone(
                        _controller_pinned_file(
                            path_variable, digest_variable, 1024, "trusted root"
                        )
                    )
                with mock.patch.dict(
                    "os.environ", {path_variable: str(root / "missing-root.json")}
                ):
                    self.assertIsNone(
                        _controller_pinned_file(
                            path_variable, digest_variable, 1024, "trusted root"
                        )
                    )
                with mock.patch(
                    "archiveweaver.readiness._read_stable_bytes",
                    side_effect=OSError("trust file replaced during read"),
                ):
                    self.assertIsNone(
                        _trusted_file_bytes(
                            path_variable, digest_variable, 1024, "trusted root"
                        )
                    )

    def test_signing_policy_rejects_ambiguous_and_unapproved_signers(self) -> None:
        repository = "Yunushan/archiveweaver"
        identity = (
            "https://github.com/Yunushan/archiveweaver/.github/workflows/"
            "release.yml@refs/tags/v1.0"
        )
        manifest = {"release": {"version": "1.0", "source_repository": repository}}
        signer = {
            "role": "release-artifact",
            "name": "product",
            "digest": "sha256:" + "a" * 64,
            "identity": identity,
            "issuer": "https://token.actions.githubusercontent.com",
        }
        policy = {
            "schema_version": 1,
            "release_version": "1.0",
            "source_repository": repository,
            "github_controls_identity": identity,
            "signers": [signer],
        }
        with tempfile.TemporaryDirectory() as directory:
            policy_file = Path(directory) / "signing-policy.json"

            def check(candidate: object) -> object:
                content = json.dumps(candidate).encode("utf-8")
                policy_file.write_bytes(content)
                with mock.patch.dict(
                    "os.environ",
                    {
                        "ARCHIVEWEAVER_SIGNING_POLICY_PATH": str(policy_file),
                        "ARCHIVEWEAVER_SIGNING_POLICY_SHA256": hashlib.sha256(
                            content
                        ).hexdigest(),
                    },
                ):
                    return _signing_policy(manifest)

            self.assertEqual(check(policy), policy)
            image_signer = {
                **signer,
                "image": "ghcr.io/example/product@" + signer["digest"],
            }
            image_policy = {**policy, "signers": [image_signer]}
            self.assertEqual(check(image_policy), image_policy)
            rollback_signer = {
                **signer,
                "role": "rollback-artifact",
                "release_version": "0.9",
            }
            rollback_policy = {**policy, "signers": [rollback_signer]}
            self.assertEqual(check(rollback_policy), rollback_policy)
            rollback_content = json.dumps(rollback_policy).encode("utf-8")
            policy_file.write_bytes(rollback_content)
            with mock.patch.dict("os.environ", {
                "ARCHIVEWEAVER_SIGNING_POLICY_PATH": str(policy_file),
                "ARCHIVEWEAVER_SIGNING_POLICY_SHA256": hashlib.sha256(
                    rollback_content
                ).hexdigest(),
            }):
                self.assertEqual(
                    _approved_signer(
                        manifest, "rollback-artifact", "product", signer["digest"],
                        release_version="0.9",
                    ),
                    (identity, signer["issuer"]),
                )
                self.assertIsNone(
                    _approved_signer(
                        manifest, "rollback-artifact", "product", signer["digest"],
                        release_version="not-the-signed-release",
                    )
                )
            missing_rollback_version = dict(rollback_signer)
            missing_rollback_version.pop("release_version")
            self.assertIsNone(check({**policy, "signers": [missing_rollback_version]}))
            image_content = json.dumps(image_policy).encode("utf-8")
            policy_file.write_bytes(image_content)
            with mock.patch.dict("os.environ", {
                "ARCHIVEWEAVER_SIGNING_POLICY_PATH": str(policy_file),
                "ARCHIVEWEAVER_SIGNING_POLICY_SHA256": hashlib.sha256(
                    image_content
                ).hexdigest(),
            }):
                self.assertEqual(
                    _approved_signer(
                        manifest, "release-artifact", "product", signer["digest"],
                        image=image_signer["image"],
                    ),
                    (identity, signer["issuer"]),
                )
                self.assertIsNone(_approved_signer(
                    manifest, "release-artifact", "product", signer["digest"]
                ))

            for malformed_content in (
                b"{\xff",
                b'{"schema_version":1,"schema_version":1}',
            ):
                with self.subTest(malformed_content=malformed_content):
                    policy_file.write_bytes(malformed_content)
                    with mock.patch.dict(
                        "os.environ",
                        {
                            "ARCHIVEWEAVER_SIGNING_POLICY_PATH": str(policy_file),
                            "ARCHIVEWEAVER_SIGNING_POLICY_SHA256": hashlib.sha256(
                                malformed_content
                            ).hexdigest(),
                        },
                    ):
                        self.assertIsNone(_signing_policy(manifest))

            invalid_signer = copy.deepcopy(signer)
            invalid_signer["identity"] = "https://github.com/owner/*"
            bad_issuer = copy.deepcopy(signer)
            bad_issuer["issuer"] = "https://[invalid"
            insecure_issuer = copy.deepcopy(signer)
            insecure_issuer["issuer"] = "http://issuer.example"
            mismatched_image = {
                **signer,
                "role": "execution-environment",
                "image": "ghcr.io/example/controller@sha256:" + "b" * 64,
            }
            mismatched_release_image = {
                **image_signer,
                "image": "ghcr.io/example/product@sha256:" + "b" * 64,
            }
            tagged_release_image = {
                **image_signer,
                "image": "ghcr.io/example/product:latest@" + signer["digest"],
            }
            for name, mutation in (
                ("wrong release", {"release_version": "2.0"}),
                ("non-object signer", {"signers": [None]}),
                ("wildcard identity", {"signers": [invalid_signer]}),
                ("malformed issuer URL", {"signers": [bad_issuer]}),
                ("insecure issuer", {"signers": [insecure_issuer]}),
                ("wrong execution image", {"signers": [mismatched_image]}),
                ("wrong release image digest", {"signers": [mismatched_release_image]}),
                ("tagged release image", {"signers": [tagged_release_image]}),
                ("duplicate signer", {"signers": [signer, copy.deepcopy(signer)]}),
            ):
                with self.subTest(name=name):
                    self.assertIsNone(check({**policy, **mutation}))

    def test_oci_image_row_requires_raw_manifest_bytes(self) -> None:
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + "1" * 64,
                "size": 2,
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:" + "2" * 64,
                "size": 10,
            }],
        }
        self.assertTrue(_oci_descriptor_ok(manifest["config"], config=True))
        self.assertTrue(_oci_descriptor_ok(manifest["layers"][0], config=False))
        self.assertFalse(_oci_descriptor_ok(None, config=True))
        self.assertFalse(_oci_descriptor_ok({**manifest["config"], "size": True}, config=True))
        self.assertFalse(_oci_descriptor_ok({**manifest["config"], "size": -1}, config=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"

            def check(content: bytes, *, expected: bool = True) -> None:
                path.write_bytes(content)
                digest = "sha256:" + hashlib.sha256(content).hexdigest()
                image = "ghcr.io/paperless-ngx/paperless-ngx@" + digest
                context = _context(root, {path.name}, self.catalog)
                self.assertEqual(
                    _oci_image_manifest_ok(path.name, image, digest, root, context),
                    expected,
                )

            valid = json.dumps(manifest).encode("utf-8")
            check(valid)
            path.write_bytes(valid)
            context = _context(root, {path.name}, self.catalog)
            valid_digest = "sha256:" + hashlib.sha256(valid).hexdigest()
            self.assertFalse(_oci_image_manifest_ok(
                path.name, "ghcr.io/paperless-ngx/paperless-ngx:latest@" + valid_digest,
                valid_digest, root, context,
            ))
            self.assertFalse(_oci_image_manifest_ok(
                path.name, "ghcr.io/paperless-ngx/paperless-ngx@" + valid_digest,
                "sha256:" + "f" * 64, root, context,
            ))
            self.assertFalse(_oci_image_manifest_ok(
                path.name, "ghcr.io/paperless-ngx/paperless-ngx@" + valid_digest,
                valid_digest, root, None,
            ))
            malformed = [
                b"not an OCI manifest tar",
                b"{",
                b"[]",
                json.dumps({**manifest, "mediaType": "application/vnd.oci.image.index.v1+json"}).encode(),
                json.dumps({**manifest, "schemaVersion": True}).encode(),
                json.dumps({**manifest, "artifactType": "application/spdx+json"}).encode(),
                json.dumps({**manifest, "subject": {"digest": valid_digest}}).encode(),
                json.dumps({**manifest, "layers": []}).encode(),
                json.dumps({**manifest, "config": {**manifest["config"], "mediaType": "application/octet-stream"}}).encode(),
                json.dumps({**manifest, "layers": [{**manifest["layers"][0], "digest": "mutable"}]}).encode(),
            ]
            for content in malformed:
                with self.subTest(content=content[:80]):
                    check(content, expected=False)

    def test_oci_image_ref_requires_explicit_registry_host(self) -> None:
        digest = "sha256:" + "a" * 64
        for repository in (
            "ghcr.io/paperless-ngx/paperless-ngx",
            "registry:5000/team/image",
            "localhost/team/image",
            "localhost:5000/team/image",
        ):
            self.assertTrue(_oci_release_image_ref_ok(repository + "@" + digest))
        for repository in (
            "paperless-ngx/paperless-ngx",
            "registry:65536/team/image",
            "registry:0/team/image",
            "registry:0001/team/image",
            "registry.example./team/image",
            "registry..example/team/image",
            "GHCR.io/team/image",
            "ghcr.io/team/image:latest",
            "ghcr.io/team//image",
        ):
            self.assertFalse(_oci_release_image_ref_ok(repository + "@" + digest))
        self.assertFalse(_oci_release_image_ref_ok(None))

    def test_image_provenance_needs_exact_signed_subject_and_dsse_bytes(self) -> None:
        repository = "ghcr.io/paperless-ngx/paperless-ngx"
        digest = "sha256:" + "a" * 64
        image = repository + "@" + digest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            statement_path = root / "image-provenance.json"
            statement_path.write_bytes(b'{"signed":"image provenance"}')
            bundle_path = root / "image-provenance.sigstore.json"
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {"rawBytes": base64.b64encode(b"cert").decode()},
                    "tlogEntries": [{
                        "canonicalizedBody": base64.b64encode(b"entry").decode()
                    }],
                },
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(statement_path.read_bytes()).decode(),
                    "signatures": [{"sig": base64.b64encode(b"sig").decode()}],
                },
            }
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            self.assertTrue(_indexed_dsse_statement_ok(
                statement_path.name, bundle_path.name, root, context
            ))
            bundle_path.write_bytes(b"{\xff")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            self.assertFalse(_indexed_dsse_statement_ok(
                statement_path.name, bundle_path.name, root, context
            ))
            bundle_path.write_text(json.dumps({"mediaType": "wrong"}), encoding="utf-8")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            self.assertFalse(_indexed_dsse_statement_ok(
                statement_path.name, bundle_path.name, root, context
            ))
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            subject = {"subject": [{"name": repository, "digest": {"sha256": "a" * 64}}]}
            artifact = root / "image-manifest.json"
            artifact.write_bytes(b"signed OCI manifest")
            row = {
                "provenance": statement_path.name,
                "provenance_bundle": bundle_path.name,
            }
            signer = ("https://example.org/approved-image-builder", "https://example.org/issuer")
            with mock.patch(
                "archiveweaver.readiness._provenance_payload", return_value=subject
            ), mock.patch(
                "archiveweaver.readiness._verify_sigstore_bundle", return_value=True
            ) as verifier:
                self.assertTrue(_image_provenance_ok(
                    row, image, digest, signer, artifact, root, context
                ))
                verifier.assert_called_once_with(
                    bundle_path.name, artifact, signer[0], signer[1], root, context,
                    attestation=True,
                )
            with mock.patch(
                "archiveweaver.readiness._provenance_payload",
                return_value={"subject": [{"name": "wrong/image", "digest": {"sha256": "a" * 64}}]},
            ), mock.patch(
                "archiveweaver.readiness._verify_sigstore_bundle", return_value=True
            ):
                self.assertFalse(_image_provenance_ok(
                    row, image, digest, signer, artifact, root, context
                ))

            bundle["dsseEnvelope"]["payload"] = base64.b64encode(b"different bytes").decode()
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            self.assertFalse(_indexed_dsse_statement_ok(
                statement_path.name, bundle_path.name, root, context
            ))
            with mock.patch(
                "archiveweaver.readiness._provenance_payload", return_value=subject
            ), mock.patch(
                "archiveweaver.readiness._verify_sigstore_bundle", return_value=True
            ):
                self.assertFalse(_image_provenance_ok(
                    row, image, digest, signer, artifact, root, context
                ))
            bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                statement_path.read_bytes()
            ).decode()
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            context = _context(root, {statement_path.name, bundle_path.name}, self.catalog)
            with mock.patch(
                "archiveweaver.readiness._provenance_payload", return_value=subject
            ), mock.patch(
                "archiveweaver.readiness._verify_sigstore_bundle", return_value=False
            ):
                self.assertFalse(_image_provenance_ok(
                    row, image, digest, signer, artifact, root, context
                ))

    def test_image_fields_fail_closed_before_signer_lookup(self) -> None:
        root = Path(".")
        self.assertFalse(_signed_artifact_ok(
            {"image": {}}, root, None, {},
        ))
        self.assertFalse(_signed_artifact_ok(
            {"image": None}, root, None, {},
        ))
        self.assertFalse(_signed_artifact_ok(
            {"image": "ghcr.io/example/product@sha256:" + "a" * 64},
            root, None, {}, signing_role="rollback-artifact",
        ))

    def test_container_release_requires_an_image_artifact(self) -> None:
        release = {
            "version": "2026.09.1",
            "provenance_verified": True,
            "artifacts": [{"name": "package-only"}],
        }
        with (
            mock.patch("archiveweaver.readiness._section_evidence_ok", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_payload", return_value={}),
            mock.patch("archiveweaver.readiness._provenance_binds_source", return_value=True),
            mock.patch("archiveweaver.readiness._release_provenance_signature_ok", return_value=True),
            mock.patch("archiveweaver.readiness._github_controls_ok", return_value=True),
            mock.patch("archiveweaver.readiness._signed_artifact_ok", return_value=True),
        ):
            for runtime, underlying in (
                ("ansible", "rke2"),
                ("ansible", "docker-swarm"),
                ("docker", None),
            ):
                service = {"runtime": runtime}
                if underlying is not None:
                    service["underlying_runtime"] = underlying
                with self.subTest(runtime=runtime, underlying=underlying):
                    self.assertFalse(_release_ok(
                        {"service": service, "release": release}, Path("."), None
                    ))

    def test_sigstore_verifier_requires_pinned_binary_and_exact_workflow_identity(self) -> None:
        approved_identity = (
            "https://github.com/Yunushan/archiveweaver/.github/workflows/"
            "release.yml@refs/tags/v0.1.0"
        )
        identity = _github_release_certificate_identity(
            "Yunushan/archiveweaver", approved_identity
        )
        self.assertEqual(identity, approved_identity)
        self.assertIsNone(_github_release_certificate_identity("other", approved_identity))
        self.assertIsNone(_github_release_certificate_identity("owner/repo", "../main"))
        assert identity is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "cosign"
            binary.write_bytes(b"controller-approved verifier")
            bundle = root / "controls.sigstore.json"
            bundle.write_bytes(b"signed bundle bytes")
            trusted_root = root / "trusted-root.json"
            trusted_root.write_bytes(b"controller-approved trust root")
            context = _context(root, {bundle.name}, self.catalog)
            environment = {
                "ARCHIVEWEAVER_COSIGN_PATH": str(binary),
                "ARCHIVEWEAVER_COSIGN_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_PATH": str(trusted_root),
                "ARCHIVEWEAVER_SIGSTORE_TRUSTED_ROOT_SHA256": hashlib.sha256(
                    trusted_root.read_bytes()
                ).hexdigest(),
                "SIGSTORE_ROOT_FILE": str(root / "untrusted-root.json"),
            }

            def inspect_command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.assertEqual(argv[:2], [str(binary), "verify-blob"])
                self.assertEqual(Path(argv[2]).read_bytes(), b"hosted controls")
                self.assertEqual(argv[3:5], ["--offline", "--bundle"])
                self.assertEqual(Path(argv[5]).read_bytes(), bundle.read_bytes())
                self.assertEqual(argv[6], "--trusted-root")
                self.assertEqual(Path(argv[7]).read_bytes(), trusted_root.read_bytes())
                self.assertEqual(argv[8:10], ["--certificate-identity", identity])
                self.assertEqual(
                    argv[10:12],
                    ["--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"],
                )
                self.assertNotIn("SIGSTORE_ROOT_FILE", kwargs["env"])
                return subprocess.CompletedProcess(argv, 0)

            with mock.patch.dict("os.environ", environment):
                with mock.patch(
                    "archiveweaver.readiness.subprocess.run",
                    side_effect=inspect_command,
                ) as process:
                    self.assertTrue(
                        _verify_sigstore_bundle(
                            bundle.name, b"hosted controls", identity,
                            "https://token.actions.githubusercontent.com", root, context
                        )
                    )
                    self.assertEqual(process.call_count, 1)

                controls = root / "github-production-controls.json"
                controls.write_bytes(b"hosted controls")
                attestation_context = _context(
                    root, {bundle.name, controls.name}, self.catalog
                )

                def inspect_attestation_command(
                    argv: list[str], **kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    self.assertEqual(
                        argv[:2], [str(binary), "verify-blob-attestation"]
                    )
                    self.assertEqual(Path(argv[2]), controls)
                    self.assertEqual(argv[3:5], ["--offline", "--bundle"])
                    self.assertEqual(Path(argv[5]).read_bytes(), bundle.read_bytes())
                    self.assertEqual(argv[-1], "--new-bundle-format")
                    self.assertNotIn("SIGSTORE_ROOT_FILE", kwargs["env"])
                    return subprocess.CompletedProcess(argv, 0)

                with mock.patch(
                    "archiveweaver.readiness.subprocess.run",
                    side_effect=inspect_attestation_command,
                ):
                    self.assertTrue(
                        _verify_sigstore_bundle(
                            bundle.name,
                            controls,
                            identity,
                            "https://token.actions.githubusercontent.com",
                            root,
                            attestation_context,
                            attestation=True,
                        )
                    )

                unindexed_report = root / "unindexed-report.bin"
                unindexed_report.write_bytes(b"hosted controls")
                with mock.patch("archiveweaver.readiness.subprocess.run") as process:
                    self.assertFalse(
                        _verify_sigstore_bundle(
                            bundle.name, unindexed_report, identity,
                            "https://token.actions.githubusercontent.com", root, context
                        )
                    )
                    process.assert_not_called()

                with mock.patch.dict(
                    "os.environ", {"ARCHIVEWEAVER_COSIGN_SHA256": "0" * 64}
                ):
                    with mock.patch("archiveweaver.readiness.subprocess.run") as process:
                        self.assertFalse(
                            _verify_sigstore_bundle(
                                bundle.name, b"hosted controls", identity,
                                "https://token.actions.githubusercontent.com", root, context
                            )
                        )
                        process.assert_not_called()

    def test_release_provenance_requires_exact_signed_dsse_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            statement = root / "release.provenance.json"
            statement.write_bytes(b'{"statement":"approved"}')
            controls = root / "github-production-controls.json"
            controls.write_bytes(b'{"audit":"approved"}')
            bundle_path = root / "release.provenance.sigstore.json"
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {"rawBytes": base64.b64encode(b"certificate").decode()},
                    "tlogEntries": [
                        {"canonicalizedBody": base64.b64encode(b"entry").decode()}
                    ],
                },
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(statement.read_bytes()).decode(),
                    "signatures": [{"sig": base64.b64encode(b"signature").decode()}],
                },
            }
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            context = _context(
                root,
                {statement.name, controls.name, bundle_path.name},
                self.catalog,
            )
            release = {
                "source_repository": "Yunushan/archiveweaver",
                "provenance": statement.name,
                "provenance_bundle": bundle_path.name,
                "github_controls": {
                    "path": controls.name,
                    "digest": "sha256:" + hashlib.sha256(controls.read_bytes()).hexdigest(),
                },
            }
            manifest = {"release": release}
            policy = {
                "github_controls_identity": (
                    "https://github.com/Yunushan/archiveweaver/.github/workflows/"
                    "release.yml@refs/tags/v2026.09.1"
                )
            }
            with (
                mock.patch("archiveweaver.readiness._signing_policy", return_value=policy),
                mock.patch(
                    "archiveweaver.readiness._verify_sigstore_bundle",
                    return_value=True,
                ) as verifier,
            ):
                self.assertTrue(
                    _release_provenance_signature_ok(release, manifest, root, context)
                )
                self.assertTrue(verifier.call_args.kwargs["attestation"])
                self.assertEqual(verifier.call_args.args[1], controls)
                wrong_controls_digest = copy.deepcopy(release)
                wrong_controls_digest["github_controls"]["digest"] = "sha256:" + "f" * 64
                verifier.reset_mock()
                self.assertFalse(_release_provenance_signature_ok(
                    wrong_controls_digest, manifest, root, context
                ))
                verifier.assert_not_called()
                modified = copy.deepcopy(bundle)
                modified["dsseEnvelope"]["payload"] = base64.b64encode(
                    b'{"statement":"forged"}'
                ).decode()
                bundle_path.write_text(json.dumps(modified), encoding="utf-8")
                modified_context = _context(
                    root,
                    {statement.name, controls.name, bundle_path.name},
                    self.catalog,
                )
                verifier.reset_mock()
                self.assertFalse(
                    _release_provenance_signature_ok(
                        release, manifest, root, modified_context
                    )
                )
                verifier.assert_not_called()
                self.assertFalse(
                    _release_provenance_signature_ok(
                        {**release, "provenance_bundle": statement.name},
                        manifest,
                        root,
                        context,
                    )
                )

    def test_hosted_control_audit_reports_each_fail_closed_boundary(self) -> None:
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        repository = "Yunushan/archiveweaver"
        repository_id = 123
        source_revision = "a" * 40
        valid_controls = [
            {"name": name, "passed": True, "detail": f"{name} verified"}
            for name in sorted(GITHUB_AUDIT_CONTROL_NAMES)
        ]
        valid_payload: object = {
            "schema_version": 1,
            "api_version": GITHUB_AUDIT_API_VERSION,
            "audited_at": "2026-09-11T12:00:00Z",
            "repository": repository,
            "repository_id": repository_id,
            "repository_node_id": "R_kgDOProduction",
            "source_revision": source_revision,
            "passed": True,
            "controls": valid_controls,
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "github-controls.json"

            def inspect(
                payload: object,
                *,
                reference_updates: dict[str, object] | None = None,
                raw: bytes | None = None,
                verification_ok: bool = True,
            ) -> list[str]:
                content = raw if raw is not None else json.dumps(payload).encode("utf-8")
                report_path.write_bytes(content)
                reference: dict[str, object] = {
                    "path": report_path.name,
                    "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "signature": "github-controls.sigstore.json",
                    "signature_verified": True,
                    "signature_verification": {"status": "pass"},
                }
                if reference_updates:
                    reference.update(reference_updates)
                with (
                    mock.patch(
                        "archiveweaver.readiness._sigstore_bundle_binds_content",
                        return_value=True,
                    ),
                    mock.patch(
                        "archiveweaver.readiness._verify_sigstore_bundle",
                        return_value=True,
                    ),
                    mock.patch(
                        "archiveweaver.readiness._signing_policy",
                        return_value={
                            "github_controls_identity": (
                                "https://github.com/Yunushan/archiveweaver/"
                                ".github/workflows/release.yml@refs/tags/v0.1.0"
                            )
                        },
                    ),
                    mock.patch(
                        "archiveweaver.readiness._evidence_record_exists",
                        return_value=verification_ok,
                    ),
                    mock.patch(
                        "archiveweaver.readiness._json_evidence_payload",
                        return_value=(
                            {
                                "artifact_digest": reference["digest"],
                                "verifier": "sigstore-verify",
                            }
                            if verification_ok
                            else None
                        ),
                    ),
                ):
                    return _github_controls_errors(
                        reference,
                        repository,
                        repository_id,
                        source_revision,
                        {"release": {"version": "2026.09.1"}},
                        root,
                        _context(root, {report_path.name}, self.catalog),
                        now=now,
                    )

            self.assertEqual(inspect(valid_payload), [])
            self.assertEqual(
                _github_controls_errors(
                    None,
                    repository,
                    repository_id,
                    source_revision,
                    {},
                    root,
                    None,
                    now=now,
                ),
                ["must be a signed hosted-control audit reference"],
            )
            invalid_path = _github_controls_errors(
                {"path": "controls.txt"},
                repository,
                repository_id,
                source_revision,
                {},
                root,
                None,
                now=now,
            )
            self.assertTrue(any("indexed JSON report" in error for error in invalid_path))

            reference_errors = inspect(
                valid_payload,
                reference_updates={
                    "extra": True,
                    "digest": "sha256:" + "0" * 64,
                    "signature_verified": False,
                },
                verification_ok=False,
            )
            self.assertTrue(any("exactly" in error for error in reference_errors))
            self.assertTrue(any("digest" in error for error in reference_errors))
            self.assertTrue(any("signature_verified" in error for error in reference_errors))
            self.assertTrue(any("signature_verification" in error for error in reference_errors))

            malformed = inspect({}, raw=b"{\xff")
            self.assertTrue(any("unambiguous UTF-8 JSON" in error for error in malformed))
            non_object = inspect([], raw=b"[]")
            self.assertTrue(any("JSON object" in error for error in non_object))

            invalid_schema = copy.deepcopy(valid_payload)
            assert isinstance(invalid_schema, dict)
            invalid_schema.update(
                {
                    "schema_version": 2,
                    "api_version": "unsupported",
                    "repository_node_id": "latest",
                    "audited_at": "invalid",
                    "passed": False,
                    "controls": [],
                }
            )
            schema_errors = inspect(invalid_schema)
            for fragment in (
                "schema_version",
                "api_version",
                "repository_node_id",
                "audited_at",
                "controls",
            ):
                self.assertTrue(
                    any(fragment in error for error in schema_errors), schema_errors
                )

            future = copy.deepcopy(valid_payload)
            assert isinstance(future, dict)
            future["audited_at"] = "2026-09-12T12:00:00Z"
            future["controls"] = [
                {"name": name, "passed": False, "detail": "failed"}
                for name in sorted(GITHUB_AUDIT_CONTROL_NAMES)
            ]
            future_errors = inspect(future)
            self.assertTrue(any("future-dated" in error for error in future_errors))
            self.assertTrue(any("every required control" in error for error in future_errors))

    def test_approval_validation_rejects_malformed_and_reversed_windows(self) -> None:
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(_approval_window_errors(None, now=now), ["governance must be an object"])
        missing = _approval_window_errors({}, now=now)
        self.assertEqual(len(missing), 2)
        self.assertTrue(any("approved_at" in error for error in missing))
        self.assertTrue(any("valid_until" in error for error in missing))
        reversed_window = _approval_window_errors(
            {
                "approved_at": "2026-09-11T11:00:00Z",
                "valid_until": "2026-09-11T10:00:00Z",
            },
            now=now,
        )
        self.assertIn(
            "governance.valid_until must be later than governance.approved_at",
            reversed_window,
        )

    def test_evidence_freshness_is_domain_specific_and_backup_tracks_rpo(self) -> None:
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        manifest = {"data_protection": {"rpo_minutes": 60}}

        def timestamp(age: timedelta) -> str:
            return (now - age).isoformat().replace("+00:00", "Z")

        self.assertTrue(
            _evidence_timestamp_is_fresh(
                timestamp(timedelta(days=6)),
                manifest,
                "security.vulnerability_scan",
                now=now,
            )
        )
        self.assertFalse(
            _evidence_timestamp_is_fresh(
                timestamp(timedelta(days=8)),
                manifest,
                "security.vulnerability_scan",
                now=now,
            )
        )
        self.assertTrue(
            _evidence_timestamp_is_fresh(
                timestamp(timedelta(days=364)),
                manifest,
                "security.penetration_test",
                now=now,
            )
        )
        self.assertFalse(
            _evidence_timestamp_is_fresh(
                timestamp(timedelta(minutes=66)),
                manifest,
                "data_protection.backup",
                now=now,
            )
        )

        stale_scan = {
            "status": "pass",
            "name": "vulnerability scan",
            "evidence": "scan.json",
            "solution": "paperless-ngx",
            "runtime": "rke2",
            "os_id": "ubuntu-24.04",
            "release": "2026.09.1",
            "environment": "production",
            "recorded_at": timestamp(timedelta(days=8)),
            "operator": "security-automation",
            "fixture_set": "production-security-v1",
        }
        evidence_manifest = {
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "rke2",
                "os_id": "ubuntu-24.04",
                "environment": "production",
            },
            "release": {"version": "2026.09.1"},
            "security": {"vulnerability_scan": stale_scan},
        }
        self.assertIn(
            "security.vulnerability_scan.recorded_at exceeds the 7 days freshness window",
            _evidence_metadata_errors(evidence_manifest, now=now),
        )

    def test_relative_paths_and_proof_collectors_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "proof.txt"
            proof.write_text("proof\n", encoding="utf-8")
            context = _context(root, {"proof.txt"}, self.catalog)
            self.assertEqual(_relative_candidate("proof.txt", root), proof.resolve())
            for value in (
                None,
                "",
                "latest-proof.txt",
                "../proof.txt",
                "nested\\proof.txt",
                "C:\\proof.txt",
                "proof\x00.txt",
            ):
                with self.subTest(value=value):
                    self.assertIsNone(_relative_candidate(value, root))

            with mock.patch(
                "archiveweaver.readiness.has_symlink_component", return_value=True
            ):
                self.assertIsNone(_relative_candidate("proof.txt", root))
            with (
                mock.patch(
                    "archiveweaver.readiness.has_symlink_component", return_value=False
                ),
                mock.patch.object(Path, "is_symlink", return_value=True),
            ):
                self.assertIsNone(_relative_candidate("proof.txt", root))
            with (
                mock.patch(
                    "archiveweaver.readiness.has_symlink_component", return_value=False
                ),
                mock.patch.object(Path, "is_symlink", side_effect=OSError("denied")),
            ):
                self.assertIsNone(_relative_candidate("proof.txt", root))

            self.assertFalse(
                _evidence_payload_matches(
                    {"evidence": "proof.txt"}, root, context, {}
                )
            )
            self.assertFalse(_evidence_metadata_matches(None, {}))
            self.assertIsNone(_json_evidence_payload(None, root, context))
            self.assertEqual(_artifact_proof_paths(None), set())
            self.assertEqual(_execution_environment_proof_paths(None), set())
            self.assertEqual(_release_proof_paths(None), set())
            self.assertEqual(_release_proof_paths({"artifacts": "invalid"}), set())

    def test_verified_context_rechecks_exact_indexed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "proof.json"
            proof.write_text('{"value":"first"}\n', encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            index_digest = "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
            context = _evidence_context(
                {
                    "evidence_index": "evidence-index.json",
                    "evidence_index_digest": index_digest,
                },
                root,
                self.catalog,
            )
            self.assertIsNotNone(context)
            reference = {"evidence": "proof.json"}
            self.assertEqual(
                _json_evidence_payload(reference, root, context), {"value": "first"}
            )

            proof.write_text('{"value":"other"}\n', encoding="utf-8")
            self.assertIsNone(_json_evidence_payload(reference, root, context))

    def test_structured_payloads_cover_cyclonedx_and_group_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payloads = {
                "cyclonedx.json": {
                    "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.7",
                    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                    "version": 1,
                    "metadata": {
                        "timestamp": "2026-09-11T12:00:00Z",
                        "component": {
                            "type": "application",
                            "name": "product-artifact",
                            "version": "2026.09.1",
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                        },
                    },
                    "components": [
                        {
                            "bom-ref": "pkg:pypi/archiveweaver@0.1.0",
                            "type": "application",
                            "name": "product-artifact",
                            "version": "2026.09.1",
                        }
                    ],
                },
                "groups.json": {
                    "text": "build-result",
                    "items": [{"name": "item"}],
                    "mapping": {"name": "value"},
                },
                "array.json": [],
            }
            for name, payload in payloads.items():
                (root / name).write_text(json.dumps(payload), encoding="utf-8")
            context = _context(root, payloads, self.catalog)

            cyclone = _sbom_payload("cyclonedx.json", root, context)
            self.assertEqual(cyclone, payloads["cyclonedx.json"])
            self.assertTrue(
                _sbom_binds_name(
                    "cyclonedx.json", "product-artifact", root, context
                )
            )
            self.assertTrue(_sbom_binds_named_sha256(
                "cyclonedx.json", "product-artifact", "sha256:" + "a" * 64,
                root, context,
            ))
            self.assertFalse(_sbom_binds_named_sha256(
                "cyclonedx.json", "product-artifact", "sha256:" + "b" * 64,
                root, context,
            ))
            self.assertFalse(_sbom_binds_named_sha256(
                "cyclonedx.json", "dependency", "sha256:" + "a" * 64,
                root, context,
            ))
            self.assertEqual(
                _structured_json_payload(
                    "groups.json",
                    root,
                    context,
                    (("text",), ("items",), ("mapping",)),
                ),
                payloads["groups.json"],
            )
            self.assertIsNone(
                _structured_json_payload("array.json", root, context, (("items",),))
            )
            self.assertIsNone(
                _structured_json_payload("missing.json", root, context, (("items",),))
            )
            with mock.patch(
                "archiveweaver.readiness._sbom_payload",
                return_value={"packages": {"name": "invalid"}},
            ):
                self.assertFalse(
                    _sbom_binds_name("unused.json", "artifact", root, context)
                )

    def test_cyclonedx_rejects_malformed_component_types_without_crashing(self) -> None:
        payload = {
            "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2026-09-11T12:00:00Z",
                "component": {"type": "application", "name": "artifact"},
            },
            "components": [{"type": [], "name": "artifact"}],
        }
        self.assertFalse(_cyclonedx_sbom_valid(payload))

    def test_supply_chain_documents_require_production_profiles(self) -> None:
        self.assertIsNone(_spdx_packages({"packages": ["invalid"]}))
        self.assertIsNone(
            _spdx_packages(
                {
                    "packages": [
                        {
                            "SPDXID": "SPDXRef-Package-subject",
                            "name": "subject",
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": "false",
                        }
                    ]
                }
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spdx = {
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": "2026-09-11T12:00:00Z",
                    "creators": ["Tool: readiness-test"],
                },
                "dataLicense": "CC0-1.0",
                "documentDescribes": ["SPDXRef-Package-subject"],
                "documentNamespace": "https://example.org/spdx/subject/1",
                "name": "subject-sbom",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-subject",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "name": "subject",
                        "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}],
                    },
                    {
                        "SPDXID": "SPDXRef-Package-decoy",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "name": "decoy",
                    },
                ],
                "spdxVersion": "SPDX-2.3",
            }
            provenance = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": "subject", "digest": {"sha256": "a" * 64}}
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://example.org/build/v1",
                        "externalParameters": {},
                    },
                    "runDetails": {
                        "builder": {"id": "https://example.org/builder/v1"}
                    },
                },
            }
            payloads = {
                "valid.spdx.json": spdx,
                "minimal.spdx.json": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [{"name": "subject"}],
                },
                "valid-provenance.json": provenance,
                "minimal-provenance.json": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": provenance["subject"],
                    "predicateType": "https://slsa.dev/provenance/v1",
                },
            }
            for name, payload in payloads.items():
                (root / name).write_text(json.dumps(payload), encoding="utf-8")
            context = _context(root, payloads, self.catalog)

            self.assertEqual(_sbom_payload("valid.spdx.json", root, context), spdx)
            self.assertTrue(
                _sbom_binds_name("valid.spdx.json", "subject", root, context)
            )
            self.assertTrue(_sbom_binds_named_sha256(
                "valid.spdx.json", "subject", "sha256:" + "a" * 64,
                root, context,
            ))
            self.assertFalse(_sbom_binds_named_sha256(
                "valid.spdx.json", "subject", "sha256:" + "b" * 64,
                root, context,
            ))
            self.assertFalse(_sbom_binds_named_sha256(
                "valid.spdx.json", "decoy", "sha256:" + "a" * 64,
                root, context,
            ))
            self.assertFalse(_sbom_binds_named_sha256(
                "valid.spdx.json", "subject", "mutable",
                root, context,
            ))
            self.assertFalse(
                _sbom_binds_name("valid.spdx.json", "decoy", root, context)
            )
            self.assertIsNone(_sbom_payload("minimal.spdx.json", root, context))
            self.assertFalse(_sbom_binds_named_sha256(
                "minimal.spdx.json", "subject", "sha256:" + "a" * 64,
                root, context,
            ))
            with mock.patch(
                "archiveweaver.readiness._sbom_payload",
                return_value={"spdxVersion": "SPDX-2.3"},
            ):
                self.assertFalse(_sbom_binds_named_sha256(
                    "valid.spdx.json", "subject", "sha256:" + "a" * 64,
                    root, context,
                ))
            self.assertEqual(
                _provenance_payload("valid-provenance.json", root, context),
                provenance,
            )
            self.assertIsNone(
                _provenance_payload("minimal-provenance.json", root, context)
            )

    def test_attestation_subject_normalization_ignores_malformed_entries(self) -> None:
        digest_a = "a" * 64
        digest_b = "b" * 64
        payload = {
            "subject": [
                "invalid",
                {"name": "artifact", "digest": "invalid"},
                {"name": "latest", "digest": {"sha256": "c" * 64}},
                {"name": "artifact", "digest": {"sha256": "invalid"}},
                {
                    "name": "artifact",
                    "digest": {"sha512": "ignored", "SHA256": f"sha256:{digest_a}"},
                },
                {"name": "dependency", "digest": {"sha256": digest_b}},
            ]
        }
        expected_digests = {f"sha256:{digest_a}", f"sha256:{digest_b}", f"sha256:{'c' * 64}"}
        self.assertEqual(_attestation_subject_digests(payload), expected_digests)
        expected_bindings = {
            ("artifact", f"sha256:{digest_a}"),
            ("dependency", f"sha256:{digest_b}"),
        }
        self.assertEqual(_attestation_subject_bindings(payload), expected_bindings)
        self.assertEqual(_attestation_subject_digests({"subject": {}}), set())
        self.assertEqual(_attestation_subject_bindings({"subject": {}}), set())
        self.assertFalse(_provenance_binds_digests(None, expected_digests))
        self.assertFalse(_provenance_binds_digests(payload, set()))
        self.assertTrue(_provenance_binds_digests(payload, {f"sha256:{digest_a}"}))
        self.assertFalse(_provenance_binds_subjects(None, expected_bindings))
        self.assertFalse(_provenance_binds_subjects(payload, set()))
        self.assertTrue(
            _provenance_binds_subjects(payload, {("artifact", f"sha256:{digest_a}")})
        )
        source_payload = {
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {
                            "uri": "git+https://github.com/Example/ArchiveWeaver.git@refs/tags/v1",
                            "digest": {"gitCommit": "d" * 40},
                        }
                    ]
                }
            }
        }
        self.assertTrue(
            _provenance_binds_source(
                source_payload, "example/archiveweaver", "d" * 40
            )
        )
        self.assertFalse(
            _provenance_binds_source(
                source_payload, "example/archiveweaver", "e" * 40
            )
        )
        self.assertFalse(_provenance_binds_source(None, "example/archiveweaver", "d" * 40))
        self.assertFalse(
            _provenance_binds_source(
                {"predicate": {"buildDefinition": {"resolvedDependencies": {}}}},
                "example/archiveweaver",
                "d" * 40,
            )
        )
        source_payload["predicate"]["buildDefinition"]["resolvedDependencies"].insert(
            0, None
        )
        self.assertTrue(
            _provenance_binds_source(
                source_payload, "example/archiveweaver", "d" * 40
            )
        )

        with mock.patch(
            "archiveweaver.readiness._structured_json_payload",
            return_value={"subject": {}, "predicate": {}},
        ):
            self.assertIsNone(_provenance_payload("unused.json", Path("."), None))

    def test_artifact_and_execution_environment_primitives_reject_bad_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"artifact")
            context = _context(root, {"artifact.bin"}, self.catalog)
            self.assertFalse(_digest_matches("artifact.bin", "invalid", root, context))
            self.assertFalse(_signed_artifact_ok(None, root, context, {}))
            self.assertFalse(_execution_environment_ok(None, root, context, {}))
            self.assertFalse(
                _execution_environment_ok(
                    {"image": "mutable:latest", "digest": "sha256:" + "a" * 64},
                    root,
                    context,
                    {},
                )
            )
            image = "registry.example/controller@sha256:" + "a" * 64
            controller = {
                "name": "controller",
                "image": image,
                "digest": "sha256:" + "a" * 64,
                "provenance_verified": True,
                "signature_verified": True,
                "signature_verification": {"status": "pass"},
            }
            with (
                mock.patch("archiveweaver.readiness._approved_signer", return_value=("approved", "issuer")),
                mock.patch("archiveweaver.readiness._provenance_payload", return_value={}),
                mock.patch("archiveweaver.readiness._provenance_binds_digests", return_value=True),
                mock.patch("archiveweaver.readiness._provenance_binds_subjects", return_value=True),
                mock.patch("archiveweaver.readiness._provenance_binds_source", return_value=True),
                mock.patch("archiveweaver.readiness._sbom_binds_name", return_value=True),
                mock.patch("archiveweaver.readiness._evidence_exists", return_value=False),
            ):
                self.assertFalse(_execution_environment_ok(
                    controller, root, context, {"release": {}}
                ))
            self.assertFalse(
                _execution_environment_ok(
                    {
                        "image": "registry.example/controller@sha256:" + "a" * 64,
                        "digest": "sha256:" + "b" * 64,
                    },
                    root,
                    context,
                    {},
                )
            )

    def test_index_release_and_product_short_circuits_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proof.txt").write_text("proof\n", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            index_digest = "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
            self.assertEqual(
                _evidence_index_errors(
                    {
                        "evidence_index": "evidence-index.json",
                        "evidence_index_digest": index_digest,
                    },
                    root,
                ),
                [],
            )
            context = _context(root, {"proof.txt"}, self.catalog)
            self.assertFalse(_all_pass_with_evidence([], root, context))
            self.assertFalse(_claim_evidence_ok("security", None, root, context, {}))

            release = {
                "status": "pass",
                "version": "1.0",
                "provenance": "provenance.json",
                "provenance_bundle": "provenance.sigstore.json",
                "provenance_verified": True,
                "github_controls": {
                    "path": "github-controls.json",
                    "signature": "github-controls.sigstore.json",
                    "signature_verification": {
                        "evidence": "github-controls-signature-verification.json"
                    },
                },
                "artifacts": [],
            }
            with (
                mock.patch(
                    "archiveweaver.readiness._section_evidence_ok", return_value=True
                ),
                mock.patch(
                    "archiveweaver.readiness._provenance_payload", return_value={}
                ),
            ):
                self.assertFalse(_release_ok({"release": release}, root, context))

            artifact = {
                "name": "product",
                "path": "artifact.bin",
                "sbom": "artifact.spdx.json",
                "signature": "artifact.sig",
                "digest": "sha256:" + "a" * 64,
            }
            release["artifacts"] = [artifact]
            patches = (
                mock.patch(
                    "archiveweaver.readiness._section_evidence_ok", return_value=True
                ),
                mock.patch(
                    "archiveweaver.readiness._provenance_payload", return_value={}
                ),
                mock.patch(
                    "archiveweaver.readiness._signed_artifact_ok", return_value=True
                ),
                mock.patch(
                    "archiveweaver.readiness._provenance_binds_digests",
                    return_value=True,
                ),
                mock.patch(
                    "archiveweaver.readiness._provenance_binds_subjects",
                    return_value=True,
                ),
                mock.patch(
                    "archiveweaver.readiness._provenance_binds_source",
                    return_value=True,
                ),
                mock.patch(
                    "archiveweaver.readiness._release_provenance_signature_ok",
                    return_value=True,
                ),
                mock.patch(
                    "archiveweaver.readiness._github_controls_ok",
                    return_value=True,
                ),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
                patches[7],
            ):
                self.assertTrue(
                    _release_ok(
                        {"service": {"runtime": "raw"}, "release": release},
                        root,
                        context,
                    )
                )
                ansible_release = copy.deepcopy(release)
                ansible_release["provider_bundle"] = {
                    **artifact,
                    "path": "provider.bin",
                    "sbom": "provider.spdx.json",
                    "signature": "provider.sig",
                }
                self.assertFalse(
                    _release_ok(
                        {
                            "service": {"runtime": "ansible"},
                            "release": ansible_release,
                        },
                        root,
                        context,
                    )
                )

                product = {"product_certification": {"status": "pass"}}
                self.assertFalse(_product_ok(product, root, context))
                product["service"] = {"solution_id": "missing"}
                self.assertFalse(_product_ok(product, root, context))

    def test_evidence_context_and_index_failures_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = root / "evidence-index.json"
            index_path.write_text("{}\n", encoding="utf-8")
            manifest = {
                "evidence_index": index_path.name,
                "evidence_index_digest": "sha256:" + "a" * 64,
            }

            with mock.patch(
                "archiveweaver.readiness.verify_evidence_index",
                side_effect=OSError("unreadable"),
            ):
                self.assertIsNone(_evidence_context(manifest, root, self.catalog))
                self.assertTrue(
                    any(
                        "unreadable" in error
                        for error in _evidence_index_errors(manifest, root)
                    )
                )

            with mock.patch(
                "archiveweaver.readiness.verify_evidence_index",
                return_value={"status": "pass", "_entries": []},
            ):
                self.assertIsNone(_evidence_context(manifest, root, self.catalog))

            fake_index = mock.Mock()
            fake_index.parent.resolve.side_effect = OSError("raced")
            with (
                mock.patch(
                    "archiveweaver.readiness._relative_candidate",
                    return_value=fake_index,
                ),
                mock.patch(
                    "archiveweaver.readiness.verify_evidence_index",
                    return_value={"status": "pass", "_entries": {}},
                ),
            ):
                self.assertIsNone(_evidence_context(manifest, root, self.catalog))

            proof = root / "proof.txt"
            proof.write_text("proof\n", encoding="utf-8")
            context = _context(root, {proof.name}, self.catalog)
            record = {
                "status": "pass",
                "name": "proof",
                "evidence": proof.name,
            }
            self.assertTrue(_all_pass_with_evidence([record], root, context))
            self.assertFalse(
                _all_pass_with_evidence([record], root, context, manifest={})
            )

    def test_release_decision_rejects_incomplete_distinct_proof_sets(self) -> None:
        artifact = {
            "name": "product",
            "path": "artifact.bin",
            "sbom": "artifact.spdx.json",
            "signature": "artifact.sig",
            "digest": "sha256:" + "a" * 64,
        }
        github_controls = {
            "path": "github-controls.json",
            "digest": "sha256:" + "b" * 64,
            "signature": "github-controls.sigstore.json",
            "signature_verification": {"evidence": "github-controls-verify.json"},
        }
        release = {
            "status": "pass",
            "version": "1.0",
            "source_repository": "Yunushan/archiveweaver",
            "source_revision": "a" * 40,
            "provenance": "provenance.json",
            "provenance_bundle": "provenance.sigstore.json",
            "provenance_verified": True,
            "github_controls": github_controls,
            "artifacts": [artifact],
        }
        context = (Path("."), {}, self.catalog)
        patches = (
            mock.patch("archiveweaver.readiness._section_evidence_ok", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_payload", return_value={}),
            mock.patch("archiveweaver.readiness._signed_artifact_ok", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_binds_digests", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_binds_subjects", return_value=True),
            mock.patch("archiveweaver.readiness._provenance_binds_source", return_value=True),
            mock.patch("archiveweaver.readiness._release_provenance_signature_ok", return_value=True),
            mock.patch("archiveweaver.readiness._github_controls_ok", return_value=True),
        )
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
        ):
            empty = copy.deepcopy(release)
            empty["artifacts"] = []
            self.assertFalse(
                _release_ok(
                    {"service": {"runtime": "raw"}, "release": empty},
                    Path("."),
                    context,
                )
            )

            incomplete_artifact = copy.deepcopy(release)
            incomplete_artifact["artifacts"][0].pop("signature")
            self.assertFalse(
                _release_ok(
                    {
                        "service": {"runtime": "raw"},
                        "release": incomplete_artifact,
                    },
                    Path("."),
                    context,
                )
            )

            missing_controls = copy.deepcopy(release)
            missing_controls["github_controls"] = None
            self.assertFalse(
                _release_ok(
                    {"service": {"runtime": "raw"}, "release": missing_controls},
                    Path("."),
                    context,
                )
            )

            missing_control_path = copy.deepcopy(release)
            missing_control_path["github_controls"].pop("path")
            self.assertFalse(
                _release_ok(
                    {
                        "service": {"runtime": "raw"},
                        "release": missing_control_path,
                    },
                    Path("."),
                    context,
                )
            )

            incomplete_control_proofs = copy.deepcopy(release)
            incomplete_control_proofs["github_controls"].pop(
                "signature_verification"
            )
            self.assertFalse(
                _release_ok(
                    {
                        "service": {"runtime": "raw"},
                        "release": incomplete_control_proofs,
                    },
                    Path("."),
                    context,
                )
            )

            ansible = copy.deepcopy(release)
            ansible["provider_bundle"] = None
            ansible["execution_environment"] = None
            self.assertFalse(
                _release_ok(
                    {"service": {"runtime": "ansible"}, "release": ansible},
                    Path("."),
                    context,
                )
            )

    def test_schema_validation_reports_each_critical_malformed_contract(self) -> None:
        sections = {
            name: {"status": "pending"}
            for name in (
                "control",
                "release",
                "product_certification",
                "resilience",
                "data_protection",
                "security",
                "observability",
                "recovery",
                "governance",
                "support",
            )
        }
        manifest = {
            "schema_version": 2,
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "ansible",
                "underlying_runtime": "ansible",
                "os_id": "missing-os",
                "environment": "production",
            },
            "evidence_index": "evidence-index.json",
            **sections,
            "private_key": "-----BEGIN PRIVATE KEY-----",
        }
        manifest["control"] = []
        manifest["release"] = {
            "status": "pass",
            "version": "1.0",
            "artifacts": [],
            "provider_bundle": {},
            "execution_environment": {},
        }
        manifest["product_certification"] = {
            "status": "pass",
            "dependency_coverage": None,
            "format_coverage": None,
            "component_coverage": None,
        }
        manifest["resilience"] = {"status": "unknown"}
        manifest["recovery"] = {"status": "pass", "rollback_artifact": {}}
        manifest["governance"] = {"status": "pass"}

        errors = validate_manifest(manifest, self.catalog)
        expected_fragments = (
            "schema_version must be 1",
            "service.underlying_runtime cannot be ansible",
            "service.os_id must identify",
            "release.provider_bundle.name",
            "release.execution_environment.name",
            "release.execution_environment.image",
            "control must be an object",
            "resilience.status must be pass, pending, or fail",
            "recovery.rollback_artifact.name",
            "product_certification.dependency_coverage must be a list",
            "private-key material is not allowed",
        )
        for fragment in expected_fragments:
            with self.subTest(fragment=fragment):
                self.assertTrue(any(fragment in error for error in errors), errors)

        invalid_runtime = copy.deepcopy(manifest)
        invalid_runtime["service"]["runtime"] = "missing-runtime"
        invalid_runtime["release"]["status"] = "pending"
        runtime_errors = validate_manifest(invalid_runtime, self.catalog)
        self.assertTrue(
            any("service.runtime is not present in the catalog" in error for error in runtime_errors)
        )

        policy_catalog = Catalog()
        policy_solution = copy.deepcopy(policy_catalog.solutions["paperless-ngx"])
        policy_solution["mode_support"]["raw"] = "not-recommended"
        policy_catalog.solutions["paperless-ngx"] = policy_solution
        not_recommended = copy.deepcopy(manifest)
        not_recommended["schema_version"] = 1
        not_recommended["service"] = {
            "solution_id": "paperless-ngx",
            "runtime": "raw",
            "os_id": "ubuntu-24.04",
            "environment": "production",
        }
        not_recommended["release"]["status"] = "pending"
        support_errors = validate_manifest(not_recommended, policy_catalog)
        self.assertTrue(any("is not-recommended" in error for error in support_errors))

    def test_schema_validation_covers_hosted_and_ansible_release_boundaries(self) -> None:
        nested: object = "leaf"
        for _ in range(200):
            nested = {"nested": nested}
        shape_errors = validate_manifest(nested, self.catalog)
        self.assertTrue(any("nesting limit" in error for error in shape_errors))

        sections = {
            name: {"status": "pending"}
            for name in (
                "control",
                "product_certification",
                "resilience",
                "data_protection",
                "security",
                "observability",
                "recovery",
                "governance",
                "support",
            )
        }
        manifest = {
            "schema_version": 1,
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "ansible",
                "underlying_runtime": "rke2",
                "os_id": "ubuntu-24.04",
                "environment": "production",
            },
            "evidence_index": "evidence-index.json",
            "evidence_index_digest": "sha256:" + "a" * 64,
            "release": {
                "status": "pass",
                "version": "1.0",
                "source_repository": "Yunushan/archiveweaver",
                "source_repository_id": 123,
                "source_revision": "a" * 40,
                "github_controls": {"extra": True},
                "artifacts": "invalid",
            },
            **sections,
        }
        errors = validate_manifest(manifest, self.catalog)
        for fragment in (
            "release.github_controls must contain exactly",
            "release.github_controls.path",
            "release.github_controls.digest",
            "release.github_controls.signature",
            "release.github_controls.signature_verified",
            "release.github_controls.signature_verification",
            "release.provider_bundle is required",
            "release.execution_environment is required",
        ):
            self.assertTrue(any(fragment in error for error in errors), errors)

        digest_mismatch = copy.deepcopy(manifest)
        digest_mismatch["release"]["provider_bundle"] = {}
        digest_mismatch["release"]["execution_environment"] = {
            "name": "controller",
            "image": "registry.example/controller@sha256:" + "a" * 64,
            "digest": "sha256:" + "b" * 64,
        }
        digest_errors = validate_manifest(digest_mismatch, self.catalog)
        self.assertTrue(
            any("digest must match the image digest" in error for error in digest_errors)
        )

        raw_manifest = copy.deepcopy(manifest)
        raw_manifest["service"] = {
            "solution_id": "paperless-ngx",
            "runtime": "raw",
            "os_id": "ubuntu-24.04",
            "environment": "production",
        }
        raw_manifest["release"]["artifacts"] = []
        validate_manifest(raw_manifest, self.catalog)

    def test_evidence_metadata_rejects_unknown_policy_and_ansible_mismatches(self) -> None:
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        record = {
            "status": "pass",
            "name": "custom proof",
            "evidence": "custom.json",
            "solution": "paperless-ngx",
            "runtime": "ansible",
            "underlying_runtime": "raw",
            "os_id": "ubuntu-24.04",
            "release": "1.0",
            "environment": "production",
            "execution_environment_digest": "sha256:" + "b" * 64,
            "recorded_at": "2026-09-11T12:00:00Z",
            "operator": "release-operator",
            "fixture_set": "production-v1",
        }
        non_string = copy.deepcopy(record)
        non_string["evidence"] = 7
        whitespace = copy.deepcopy(record)
        whitespace["evidence"] = "   "
        manifest = {
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "ansible",
                "underlying_runtime": "rke2",
                "os_id": "ubuntu-24.04",
                "environment": "production",
            },
            "release": {
                "version": "1.0",
                "execution_environment": {"digest": "sha256:" + "a" * 64},
            },
            "custom": [non_string, whitespace, record],
        }
        errors = _evidence_metadata_errors(manifest, now=now)
        self.assertTrue(any("underlying_runtime" in error for error in errors))
        self.assertTrue(
            any("execution_environment_digest" in error for error in errors)
        )
        self.assertTrue(any("no approved evidence freshness policy" in error for error in errors))

    def test_assessment_deduplicates_hosted_control_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(
                json.dumps({"release": {"status": "pass"}}), encoding="utf-8"
            )
            duplicate = "release.github_controls duplicate hosted-control error"
            with (
                mock.patch(
                    "archiveweaver.readiness.validate_manifest",
                    return_value=[duplicate],
                ),
                mock.patch(
                    "archiveweaver.readiness._evidence_context",
                    return_value=(Path(directory), {}, self.catalog),
                ),
                mock.patch(
                    "archiveweaver.readiness._github_controls_errors",
                    return_value=["duplicate hosted-control error"],
                ),
            ):
                report = assess_readiness(manifest_path, self.catalog)
        self.assertEqual(report["errors"].count(duplicate), 1)


if __name__ == "__main__":
    unittest.main()
