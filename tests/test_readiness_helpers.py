from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from archiveweaver.catalog import Catalog
from archiveweaver.evidence import build_evidence_index
from archiveweaver.readiness import (
    _all_pass_with_evidence,
    _approval_window_errors,
    _artifact_proof_paths,
    _attestation_subject_bindings,
    _attestation_subject_digests,
    _claim_evidence_ok,
    _cyclonedx_sbom_valid,
    _digest_matches,
    _evidence_context,
    _evidence_index_errors,
    _evidence_metadata_errors,
    _evidence_metadata_matches,
    _evidence_payload_matches,
    _evidence_timestamp_is_fresh,
    _execution_environment_ok,
    _execution_environment_proof_paths,
    _json_evidence_payload,
    _product_ok,
    _provenance_binds_digests,
    _provenance_binds_source,
    _provenance_binds_subjects,
    _provenance_payload,
    _relative_candidate,
    _release_ok,
    _release_proof_paths,
    _sbom_binds_name,
    _sbom_payload,
    _sigstore_bundle_binds_content,
    _signed_artifact_ok,
    _structured_json_payload,
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
                {"verificationMaterial": {"certificate": {"rawBytes": "%%%"}}},
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

            bundle_path.write_text("{}\n", encoding="utf-8")
            self.assertFalse(
                _sigstore_bundle_binds_content(
                    "controls.bundle.json",
                    signed_content,
                    root,
                    _context(root, {bundle_path.name}, self.catalog),
                )
            )

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

            self.assertTrue(
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
            self.assertFalse(
                _sbom_binds_name("valid.spdx.json", "decoy", root, context)
            )
            self.assertIsNone(_sbom_payload("minimal.spdx.json", root, context))
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


if __name__ == "__main__":
    unittest.main()
