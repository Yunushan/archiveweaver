from __future__ import annotations

import base64
import copy
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from archiveweaver.catalog import Catalog
from archiveweaver.evidence import build_evidence_index as _build_evidence_index
from archiveweaver.readiness import (
    GITHUB_AUDIT_API_VERSION,
    GITHUB_AUDIT_CONTROL_NAMES,
    _approval_window_errors,
    assess_readiness,
)


def _spdx_document(subject_name: str) -> dict[str, object]:
    package_id = "SPDXRef-Package-" + hashlib.sha256(
        subject_name.encode("utf-8")
    ).hexdigest()[:16]
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-09-11T12:00:00Z",
            "creators": ["Tool: archiveweaver-readiness-tests"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [package_id],
        "documentNamespace": (
            "https://github.com/Yunushan/archiveweaver/test-spdx/"
            + hashlib.sha256(subject_name.encode("utf-8")).hexdigest()
        ),
        "name": f"{subject_name}-sbom",
        "packages": [
            {
                "SPDXID": package_id,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "name": subject_name,
                "versionInfo": "2026.09.1",
            }
        ],
        "spdxVersion": "SPDX-2.3",
    }


def _slsa_provenance(subjects: list[dict[str, object]]) -> dict[str, object]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/Attestations/GitHubActionsWorkflow/v1",
                "externalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/Yunushan/archiveweaver.git@refs/tags/v2026.09.1",
                        "digest": {"gitCommit": "a" * 40},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner/github-hosted"
                }
            },
        },
    }


class ReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_missing_manifest_is_not_ready(self) -> None:
        report = assess_readiness(Path("does-not-exist.json"), self.catalog)
        self.assertEqual(report["score"], 0)
        self.assertEqual(report["status"], "fail")

    def test_non_object_manifest_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text("[]", encoding="utf-8")
            report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["score"], 0)
            self.assertEqual(report["status"], "fail")

    def test_invalid_utf8_manifest_is_not_ready_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_bytes(b"{\xff")
            report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["score"], 0)

    def test_manifest_rejects_symlinked_directory_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "manifest.json").write_text("{}", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            report = assess_readiness(link / "manifest.json", self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["score"], 0)
            self.assertIn("regular, non-symlink", report["errors"][0])

    def test_duplicate_manifest_keys_are_not_ready_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
            report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["score"], 0)
            self.assertTrue(any("duplicate JSON object key" in error for error in report["errors"]))

    def test_deeply_nested_manifest_is_not_ready_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            quote = chr(34)
            manifest.write_text(
                ("{" + quote + "nested" + quote + ":") * 5000
                + "0"
                + "}" * 5000,
                encoding="utf-8",
            )
            report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["score"], 0)
            self.assertTrue(
                any("nesting limit" in error for error in report["errors"])
            )

    def test_oversized_manifest_is_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text('{"schema_version": 1}', encoding="utf-8")
            with patch(
                "archiveweaver.readiness.MAX_READINESS_MANIFEST_BYTES",
                manifest.stat().st_size - 1,
            ):
                report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["score"], 0)
            self.assertTrue(
                any("safety limit" in error for error in report["errors"])
            )

    def test_malformed_service_object_is_not_ready_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "service": [],
                        **{name: {"status": "pending"} for name in ("control", "release", "product_certification", "resilience", "data_protection", "security", "observability", "recovery", "governance", "support")},
                    }
                ),
                encoding="utf-8",
            )
            report = assess_readiness(manifest, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("service must be an object" in error for error in report["errors"]))

    def test_malformed_service_types_are_not_ready_without_crashing(self) -> None:
        base = {
            "schema_version": 1,
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "rke2",
                "os_id": "ubuntu-24.04",
                "environment": "production",
            },
            **{
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
            },
        }
        cases = (
            ("runtime", []),
            ("runtime", {}),
            ("environment", []),
            ("environment", {}),
            ("underlying_runtime", []),
        )
        with tempfile.TemporaryDirectory() as directory:
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    candidate = copy.deepcopy(base)
                    if field == "underlying_runtime":
                        candidate["service"]["runtime"] = "ansible"
                    candidate["service"][field] = value
                    manifest_path = Path(directory) / f"{field}-{type(value).__name__}.json"
                    manifest_path.write_text(json.dumps(candidate), encoding="utf-8")
                    report = assess_readiness(manifest_path, self.catalog)
                    self.assertEqual(report["status"], "fail")
                    self.assertGreaterEqual(len(report["errors"]), 1)

            for section_name in base:
                if section_name in {"schema_version", "service"}:
                    continue
                candidate = copy.deepcopy(base)
                candidate[section_name]["status"] = []
                manifest_path = Path(directory) / f"{section_name}-malformed-status.json"
                manifest_path.write_text(json.dumps(candidate), encoding="utf-8")
                report = assess_readiness(manifest_path, self.catalog)
                self.assertEqual(report["status"], "fail")
                self.assertTrue(
                    any(
                        f"{section_name}.status must be pass, pending, or fail" in error
                        for error in report["errors"]
                    )
                )

    def test_cli_reports_the_example_as_not_ready(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "archiveweaver",
                "readiness",
                "--manifest",
                "deploy/ansible/release-manifest.example.json",
                "--json",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "fail")

    def test_placeholder_manifest_cannot_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "service": {"solution_id": "paperless-ngx", "runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "production"},
                        "control": {"status": "pending"},
                        "release": {"status": "pending", "version": "REPLACE_WITH_RELEASE"},
                        "product_certification": {"status": "pending"},
                        "resilience": {"status": "pending"},
                        "data_protection": {"status": "pending"},
                        "security": {"status": "pending"},
                        "observability": {"status": "pending"},
                        "recovery": {"status": "pending"},
                        "governance": {"status": "pending"},
                        "support": {"status": "pending"},
                    }
                ),
                encoding="utf-8",
            )
            report = assess_readiness(manifest, self.catalog)
            self.assertLess(report["score"], 100)
            self.assertIn("release.version must be a non-placeholder pinned release", report["errors"])

    def test_service_environment_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "qa"},
                **{name: {"status": "pending"} for name in ("control", "release", "product_certification", "resilience", "data_protection", "security", "observability", "recovery", "governance", "support")},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertIn("service.environment must identify a supported target environment", report["errors"])

    def test_governance_approval_window_is_current_and_bounded(self) -> None:
        now = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
        current = {
            "approved_at": "2026-09-11T11:59:00Z",
            "valid_until": "2026-09-18T11:59:00Z",
        }
        self.assertEqual(_approval_window_errors(current, now=now), [])

        expired = {**current, "valid_until": "2026-09-11T11:59:30Z"}
        self.assertIn("governance approval has expired", _approval_window_errors(expired, now=now))

        future = {
            "approved_at": "2026-09-11T12:06:00Z",
            "valid_until": "2026-09-18T12:06:00Z",
        }
        self.assertIn("governance.approved_at must not be future-dated", _approval_window_errors(future, now=now))

        excessive = {**current, "valid_until": "2026-10-12T11:59:00Z"}
        self.assertIn("governance approval validity must not exceed 30 days", _approval_window_errors(excessive, now=now))

    def test_conditional_ansible_provider_requires_design_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "pacemaker", "os_id": "ubuntu-24.04", "environment": "production"},
                "evidence_index": "evidence-index.json",
                **{name: {"status": "pending"} for name in ("control", "release", "product_certification", "resilience", "data_protection", "security", "observability", "recovery", "governance", "support")},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertIn("service.conditional_design_approved must be true for a conditional product/runtime pairing", report["errors"])

    def test_secret_fields_and_evidence_escape_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "production"},
                "control": {"status": "pass", "evidence": "../outside.json", "catalog_validated": True, "ci_green": True},
                "release": {"status": "pending", "version": "2026.09.1", "provenance": "provenance.json", "provenance_verified": True, "artifacts": []},
                "product_certification": {"status": "pending"},
                "resilience": {"status": "pending"},
                "data_protection": {"status": "pending"},
                "security": {"status": "pending", "token": "must-not-be-here"},
                "observability": {"status": "pending"},
                "recovery": {"status": "pending"},
                "governance": {"status": "pending"},
                "support": {"status": "pending"},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertTrue(any("secret-bearing field 'token'" in error for error in report["errors"]))
            self.assertTrue(any("path field 'evidence'" in error for error in report["errors"]))
            self.assertLess(report["score"], 100)

            for key in (
                "api_token",
                "accessToken",
                "API-KEY",
                "secret_value",
                "database_password",
                "bearerToken",
            ):
                candidate = copy.deepcopy(manifest)
                candidate["security"][key] = "must-not-be-here"
                candidate_path = root / f"{key.replace('-', '_')}.json"
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                candidate_report = assess_readiness(candidate_path, self.catalog)
                self.assertTrue(
                    any(
                        f"secret-bearing field '{key}'" in error
                        for error in candidate_report["errors"]
                    )
                )

    def test_empty_referenced_evidence_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "empty.json").write_bytes(b"")
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "production"},
                "evidence_index": "evidence-index.json",
                "control": {"status": "pass", "evidence": "empty.json", "catalog_validated": True, "ci_green": True},
                **{name: {"status": "pending"} for name in ("release", "product_certification", "resilience", "data_protection", "security", "observability", "recovery", "governance", "support")},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][0]["status"], "fail")

    def test_invalid_solution_with_verified_index_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "product.json").write_text("{}\n", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "not-in-catalog", "runtime": "raw", "os_id": "ubuntu-24.04", "environment": "production"},
                "evidence_index": "evidence-index.json",
                **{name: {"status": "pending"} for name in ("control", "release", "resilience", "data_protection", "security", "observability", "recovery", "governance", "support")},
                "product_certification": {"status": "pass", "evidence": "product.json", "dependency_coverage": [], "format_coverage": [], "test_matrix": []},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("not present in the catalog" in error for error in report["errors"]))

    def test_complete_evidence_manifest_scores_100(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_root = Path(directory)
            root = manifest_root / "evidence"
            root.mkdir()
            approval_time = datetime.now(timezone.utc) - timedelta(minutes=1)
            approval_expiry = approval_time + timedelta(days=7)
            approved_at = approval_time.isoformat().replace("+00:00", "Z")
            valid_until = approval_expiry.isoformat().replace("+00:00", "Z")
            audit_time = (approval_time - timedelta(minutes=1)).isoformat().replace(
                "+00:00", "Z"
            )
            recorded_at = audit_time
            future_recorded_at = (
                approval_time + timedelta(days=1)
            ).isoformat().replace("+00:00", "Z")
            source_revision = "a" * 40
            source_repository_id = 123456
            for name in (
                "control.json", "release.json", "provenance.json", "release.spdx.json", "release.sig", "signature-verification.json", "execution-environment-provenance.json", "execution-environment.spdx.json", "execution-environment.sig", "execution-environment-signature-verification.json", "artifact.tar", "provider-bundle.tar", "provider-bundle.spdx.json", "provider-bundle.sig", "provider-bundle-signature-verification.json", "provider-bundle-verification.json", "rollback-artifact.tar", "rollback.spdx.json", "rollback.sig", "rollback-signature-verification.json", "product.json", "resilience.json",
                "product-dependencies.json", "product-smoke.json", "product-migration.json",
                "product-formats.json", "product-api.json", "failure.json", "failure-service.json",
                "failure-dependency.json", "failure-storage.json", "data.json",
                "backup.json", "restore.json", "fixity.json", "security.json", "security-sbom.json", "tls.json",
                "secrets-provider.json", "scan.json", "pentest.json", "observe.json", "metrics.json", "alerts.json",
                "dashboards.json", "on-call.json", "alert.json", "recovery.json", "rollback.json", "repair.json",
                "governance.json", "risk.json", "retention.json", "support.json", "service-owner.json", "support-on-call.json",
                "sla.json", "runbook.md", "github-production-controls.json",
                "github-production-controls.json.sigstore.json",
                "github-production-controls-signature-verification.json",
            ):
                (root / name).write_text("{}\n", encoding="utf-8")
            github_audit = {
                "schema_version": 1,
                "api_version": GITHUB_AUDIT_API_VERSION,
                "audited_at": audit_time,
                "repository": "Yunushan/archiveweaver",
                "repository_id": source_repository_id,
                "repository_node_id": "R_archiveweaver",
                "source_revision": source_revision,
                "passed": True,
                "controls": [
                    {
                        "name": name,
                        "passed": True,
                        "detail": f"verified {name} production control",
                    }
                    for name in sorted(GITHUB_AUDIT_CONTROL_NAMES)
                ],
            }
            (root / "github-production-controls.json").write_text(
                json.dumps(github_audit), encoding="utf-8"
            )
            github_audit_digest = "sha256:" + hashlib.sha256(
                (root / "github-production-controls.json").read_bytes()
            ).hexdigest()
            github_controls_bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(b"test certificate").decode()
                    },
                    "tlogEntries": [
                        {
                            "canonicalizedBody": base64.b64encode(
                                b"test transparency entry"
                            ).decode()
                        }
                    ],
                },
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(
                            hashlib.sha256(
                                (root / "github-production-controls.json").read_bytes()
                            ).digest()
                        ).decode(),
                    },
                    "signature": base64.b64encode(b"test signature").decode(),
                },
            }
            (root / "github-production-controls.json.sigstore.json").write_text(
                json.dumps(github_controls_bundle), encoding="utf-8"
            )
            (root / "provenance.json").write_text(
                json.dumps(_slsa_provenance([{"name": "product-artifact"}])),
                encoding="utf-8",
            )
            (root / "release.spdx.json").write_text(
                json.dumps(_spdx_document("product-artifact")),
                encoding="utf-8",
            )
            (root / "execution-environment-provenance.json").write_text(
                json.dumps(_slsa_provenance([{"name": "archiveweaver-ee"}])),
                encoding="utf-8",
            )
            (root / "execution-environment.spdx.json").write_text(
                json.dumps(_spdx_document("archiveweaver-ee")),
                encoding="utf-8",
            )
            (root / "execution-environment.sig").write_bytes(b"execution-environment-signature\n")
            def evidence(name, status="pass", label="evidence"):
                return {
                    "name": label,
                    "status": status,
                    "evidence": f"evidence/{name}",
                    "solution": "paperless-ngx",
                    "runtime": "ansible",
                    "underlying_runtime": "rke2",
                    "os_id": "ubuntu-24.04",
                    "release": "2026.09.1",
                    "environment": "production",
                    "execution_environment_digest": execution_environment_digest,
                    "recorded_at": recorded_at,
                    "operator": "ci",
                    "fixture_set": "archiveweaver-fixtures-v1",
                }
            artifact = root / "artifact.tar"
            artifact.write_bytes(b"approved release artifact\n")
            digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
            release_provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
            release_provenance["subject"][0]["digest"] = {"sha256": digest.split(":", 1)[1]}
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            provider_bundle = root / "provider-bundle.tar"
            provider_bundle.write_bytes(b"reviewed provider bundle\n")
            provider_bundle_digest = "sha256:" + hashlib.sha256(provider_bundle.read_bytes()).hexdigest()
            (root / "provider-bundle.spdx.json").write_text(
                json.dumps(_spdx_document("provider-bundle")),
                encoding="utf-8",
            )
            (root / "provider-bundle.sig").write_bytes(b"provider-bundle-signature\n")
            release_provenance["subject"].append(
                {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}}
            )
            release_provenance["subject"].append(
                {
                    "name": "github-production-controls.json",
                    "digest": {"sha256": github_audit_digest.split(":", 1)[1]},
                }
            )
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            rollback_artifact = root / "rollback-artifact.tar"
            rollback_artifact.write_bytes(b"approved previous release artifact\n")
            rollback_digest = "sha256:" + hashlib.sha256(rollback_artifact.read_bytes()).hexdigest()
            (root / "rollback.spdx.json").write_text(
                json.dumps(_spdx_document("previous-product-artifact")),
                encoding="utf-8",
            )
            (root / "rollback.sig").write_bytes(b"rollback-signature\n")
            execution_environment_digest = "sha256:" + "c" * 64
            execution_environment_provenance = json.loads(
                (root / "execution-environment-provenance.json").read_text(encoding="utf-8")
            )
            execution_environment_provenance["subject"][0]["digest"] = {
                "sha256": execution_environment_digest.split(":", 1)[1]
            }
            (root / "execution-environment-provenance.json").write_text(
                json.dumps(execution_environment_provenance), encoding="utf-8"
            )
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "production"},
                "evidence_index": "evidence/evidence-index.json",
                "control": {"status": "pass", "evidence": "control.json", "catalog_validated": True, "ci_green": True, "change_ticket": "CHG-1234"},
                "release": {"status": "pass", "evidence": "release.json", "version": "2026.09.1", "source_repository": "Yunushan/archiveweaver", "source_repository_id": source_repository_id, "source_revision": source_revision, "github_controls": {"path": "evidence/github-production-controls.json", "digest": github_audit_digest, "signature": "evidence/github-production-controls.json.sigstore.json", "signature_verified": True, "signature_verification": evidence("github-production-controls-signature-verification.json", label="GitHub production controls signature")}, "provenance": "evidence/provenance.json", "provenance_verified": True, "artifacts": [{"name": "product-artifact", "path": "evidence/artifact.tar", "digest": digest, "sbom": "evidence/release.spdx.json", "signature": "evidence/release.sig", "signature_verified": True, "signature_verification": evidence("signature-verification.json", label="signature")}], "provider_bundle": {"name": "provider-bundle", "path": "evidence/provider-bundle.tar", "digest": provider_bundle_digest, "remote_digest": provider_bundle_digest, "sbom": "evidence/provider-bundle.spdx.json", "signature": "evidence/provider-bundle.sig", "signature_verified": True, "signature_verification": evidence("provider-bundle-signature-verification.json", label="provider bundle signature"), "verification": evidence("provider-bundle-verification.json", label="provider-bundle")}},
                "product_certification": {
                    "status": "pass",
                    "evidence": "product.json",
                    "dependency_coverage": ["Python", "PostgreSQL", "Redis", "Tesseract", "OCRmyPDF", "Ghostscript", "Gotenberg", "Tika"],
                    "format_coverage": ["documents", "images", "email", "archives", "structured"],
                    "component_coverage": ["Django web", "Celery workers", "PostgreSQL", "Redis", "Tika/Gotenberg", "OCRmyPDF/Tesseract", "media storage"],
                    "test_matrix": [evidence(name, label=label) for name, label in [("product-dependencies.json", "dependencies"), ("product-smoke.json", "smoke"), ("product-migration.json", "migration"), ("product-formats.json", "formats"), ("product-api.json", "api")]],
                },
                "resilience": {"status": "pass", "evidence": "resilience.json", "quorum_verified": True, "fencing_verified": True, "failure_tests": [evidence(name, label=label) for name, label in [("failure.json", "node"), ("failure-service.json", "service"), ("failure-dependency.json", "dependency"), ("failure-storage.json", "storage")]]},
                "data_protection": {"status": "pass", "evidence": "data.json", "rpo_minutes": 60, "rto_minutes": 240, "backup": {"status": "pass", "evidence": "backup.json", "immutable_copies": 2}, "restore_test": evidence("restore.json"), "fixity_test": evidence("fixity.json")},
                "security": {"status": "pass", "evidence": "security.json", "sbom_verified": True, "tls_verified": True, "secrets_provider": "vault", "sbom_verification": evidence("security-sbom.json", label="security sbom"), "tls_verification": evidence("tls.json", label="tls"), "secrets_provider_verification": evidence("secrets-provider.json", label="secrets provider"), "vulnerability_scan": evidence("scan.json"), "penetration_test": evidence("pentest.json")},
                "observability": {"status": "pass", "evidence": "observe.json", "metrics": "prometheus", "alerts": "pager", "dashboards": "grafana", "on_call": "platform-oncall", "metrics_verification": evidence("metrics.json", label="metrics"), "alerts_verification": evidence("alerts.json", label="alerts"), "dashboards_verification": evidence("dashboards.json", label="dashboards"), "on_call_verification": evidence("on-call.json", label="observability on-call"), "alert_delivery_test": evidence("alert.json", label="alert delivery")},
                "recovery": {"status": "pass", "evidence": "recovery.json", "rollback_release": "2026.09.0", "rollback_artifact_digest": rollback_digest, "rollback_artifact": {"name": "previous-product-artifact", "path": "evidence/rollback-artifact.tar", "digest": rollback_digest, "sbom": "evidence/rollback.spdx.json", "signature": "evidence/rollback.sig", "signature_verified": True, "signature_verification": evidence("rollback-signature-verification.json", label="rollback signature")}, "rollback_test": evidence("rollback.json"), "repair_test": evidence("repair.json")},
                "governance": {"status": "pass", "evidence": "governance.json", "change_ticket": "CHG-1234", "approved_by": "ops@example.org", "approved_at": approved_at, "valid_until": valid_until, "evidence_immutable": True, "evidence_access_logged": True, "evidence_retention_days": 2555, "retention_control": evidence("retention.json", label="retention"), "risk_review": evidence("risk.json")},
                "support": {"status": "pass", "evidence": "support.json", "service_owner": "Archive Platform", "on_call": "platform-oncall", "sla": "99.9%", "service_owner_verification": evidence("service-owner.json", label="service owner"), "on_call_verification": evidence("support-on-call.json", label="support on-call"), "sla_verification": evidence("sla.json", label="SLA"), "rpo_minutes": 60, "rto_minutes": 240, "runbooks": ["evidence/runbook.md"]},
            }
            for section_name in (
                "control", "release", "product_certification", "resilience", "data_protection",
                "security", "observability", "recovery", "governance", "support",
            ):
                manifest[section_name].update(evidence(manifest[section_name]["evidence"], label=section_name))
            manifest["data_protection"]["backup"].update(evidence("backup.json", label="backup"))
            manifest["release"]["artifacts"][0]["signature_verification"].update({"artifact_digest": digest, "verifier": "cosign"})
            manifest["release"]["provider_bundle"]["signature_verification"].update({"artifact_digest": provider_bundle_digest, "verifier": "cosign"})
            manifest["release"]["provider_bundle"]["verification"].update({"artifact_digest": provider_bundle_digest, "remote_digest": provider_bundle_digest, "verifier": "ansible-provider-check"})
            manifest["release"]["github_controls"]["signature_verification"].update({"artifact_digest": github_audit_digest, "verifier": "sigstore verify identity"})
            manifest["recovery"]["rollback_artifact"]["signature_verification"].update({"artifact_digest": rollback_digest, "verifier": "cosign"})
            manifest["release"]["execution_environment"] = {
                "name": "archiveweaver-ee",
                "image": "registry.example/archiveweaver-ee@" + execution_environment_digest,
                "digest": execution_environment_digest,
                "provenance": "evidence/execution-environment-provenance.json",
                "provenance_verified": True,
                "sbom": "evidence/execution-environment.spdx.json",
                "signature": "evidence/execution-environment.sig",
                "signature_verified": True,
                "signature_verification": evidence("execution-environment-signature-verification.json", label="execution environment signature"),
            }
            manifest["release"]["execution_environment"]["signature_verification"].update({"artifact_digest": execution_environment_digest, "verifier": "cosign"})

            def write_evidence_payloads(value):
                if isinstance(value, dict):
                    if value.get("status") == "pass" and isinstance(value.get("evidence"), str):
                        (manifest_root / value["evidence"]).write_text(
                            json.dumps(value), encoding="utf-8"
                        )
                    for child in value.values():
                        write_evidence_payloads(child)
                elif isinstance(value, list):
                    for child in value:
                        write_evidence_payloads(child)

            write_evidence_payloads(manifest)
            manifest_path = manifest_root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            def build_evidence_index(directory_path: Path, output_path: Path):
                result = _build_evidence_index(directory_path, output_path)
                manifest["evidence_index_digest"] = (
                    "sha256:" + hashlib.sha256(output_path.read_bytes()).hexdigest()
                )
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                return result

            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["score"], 100)

            invalid_audits = []
            candidate = copy.deepcopy(github_audit)
            candidate["passed"] = False
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["controls"][0]["passed"] = False
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["controls"][0]["name"] = candidate["controls"][1]["name"]
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["controls"][0]["unexpected"] = True
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["repository"] = "other/archiveweaver"
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["repository_id"] += 1
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["source_revision"] = "b" * 40
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["unexpected"] = True
            invalid_audits.append(candidate)
            candidate = copy.deepcopy(github_audit)
            candidate["audited_at"] = "2000-01-01T00:00:00Z"
            invalid_audits.append(candidate)

            audit_path = root / "github-production-controls.json"
            for invalid_audit in invalid_audits:
                with self.subTest(invalid_audit=invalid_audit):
                    audit_path.write_text(json.dumps(invalid_audit), encoding="utf-8")
                    invalid_digest = "sha256:" + hashlib.sha256(
                        audit_path.read_bytes()
                    ).hexdigest()
                    github_controls = manifest["release"]["github_controls"]
                    github_controls["digest"] = invalid_digest
                    github_controls["signature_verification"][
                        "artifact_digest"
                    ] = invalid_digest
                    write_evidence_payloads(manifest)
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    build_evidence_index(root, index_path)
                    report = assess_readiness(manifest_path, self.catalog)
                    self.assertEqual(report["criteria"][1]["status"], "fail")
                    self.assertTrue(
                        any("release.github_controls" in error for error in report["errors"])
                    )
            audit_path.write_text(json.dumps(github_audit), encoding="utf-8")
            manifest["release"]["github_controls"]["digest"] = github_audit_digest
            manifest["release"]["github_controls"]["signature_verification"][
                "artifact_digest"
            ] = github_audit_digest
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, index_path)

            source_dependency = release_provenance["predicate"]["buildDefinition"][
                "resolvedDependencies"
            ][0]
            source_dependency["digest"]["gitCommit"] = "b" * 40
            (root / "provenance.json").write_text(
                json.dumps(release_provenance), encoding="utf-8"
            )
            build_evidence_index(root, index_path)
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            source_dependency["digest"]["gitCommit"] = source_revision
            (root / "provenance.json").write_text(
                json.dumps(release_provenance), encoding="utf-8"
            )
            build_evidence_index(root, index_path)

            index_document = json.loads(index_path.read_text(encoding="utf-8"))
            index_path.write_text(
                json.dumps(index_document, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(
                any("evidence index digest mismatch" in error for error in report["errors"])
            )
            build_evidence_index(root, index_path)

            original_release_sbom = (root / "release.spdx.json").read_text(encoding="utf-8")
            (root / "release.spdx.json").write_text(
                json.dumps(_spdx_document("unrelated-artifact")),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.spdx.json").write_text(original_release_sbom, encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            original_signature_path = manifest["release"]["artifacts"][0]["signature"]
            manifest["release"]["artifacts"][0]["signature"] = manifest["release"]["artifacts"][0]["path"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            manifest["release"]["artifacts"][0]["signature"] = original_signature_path
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            original_execution_environment_signature = manifest["release"]["execution_environment"]["signature"]
            manifest["release"]["execution_environment"]["signature"] = original_signature_path
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            manifest["release"]["execution_environment"]["signature"] = original_execution_environment_signature
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            original_rollback_signature = manifest["recovery"]["rollback_artifact"]["signature"]
            manifest["recovery"]["rollback_artifact"]["signature"] = original_signature_path
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][7]["status"], "fail")
            manifest["recovery"]["rollback_artifact"]["signature"] = original_rollback_signature
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            original_product_subject_name = release_provenance["subject"][0]["name"]
            release_provenance["subject"][0]["name"] = "unrelated-artifact"
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            release_provenance["subject"][0]["name"] = original_product_subject_name
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            first_product_test = manifest["product_certification"]["test_matrix"][0]
            first_product_test["execution_environment"] = {"artifacts": [], "provider_bundle": {}}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][2]["status"], "fail")
            self.assertTrue(any("execution_environment must identify a supported execution environment" in error for error in report["errors"]))
            first_product_test.pop("execution_environment")

            manifest["release"]["artifacts"].append(dict(manifest["release"]["artifacts"][0]))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            self.assertTrue(any("duplicate artifact names" in error for error in report["errors"]))
            manifest["release"]["artifacts"].pop()

            original_resilience_evidence = manifest["resilience"]["evidence"]
            manifest["resilience"]["evidence"] = "failure.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][3]["status"], "fail")
            manifest["resilience"]["evidence"] = original_resilience_evidence

            resilience_evidence_path = root / "resilience.json"
            resilience_payload = json.loads(
                resilience_evidence_path.read_text(encoding="utf-8")
            )
            resilience_payload["quorum_verified"] = False
            resilience_evidence_path.write_text(
                json.dumps(resilience_payload), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][3]["status"], "fail")
            write_evidence_payloads(manifest)
            build_evidence_index(root, root / "evidence-index.json")

            for section_name, field_name, criterion_index in (
                ("security", "sbom_verification", 5),
                ("security", "tls_verification", 5),
                ("security", "secrets_provider_verification", 5),
                ("observability", "metrics_verification", 6),
                ("observability", "alerts_verification", 6),
                ("observability", "dashboards_verification", 6),
                ("observability", "on_call_verification", 6),
                ("support", "service_owner_verification", 9),
                ("support", "on_call_verification", 9),
                ("support", "sla_verification", 9),
            ):
                removed = manifest[section_name].pop(field_name)
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                build_evidence_index(root, root / "evidence-index.json")
                report = assess_readiness(manifest_path, self.catalog)
                self.assertEqual(report["criteria"][criterion_index]["status"], "fail")
                self.assertTrue(any(f"{section_name}.{field_name}" in error for error in report["errors"]))
                manifest[section_name][field_name] = removed

            original_security_evidence = manifest["security"]["secrets_provider_verification"]["evidence"]
            manifest["security"]["secrets_provider_verification"]["evidence"] = manifest["security"]["tls_verification"]["evidence"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][5]["status"], "fail")
            self.assertTrue(any("reused by multiple records" in error for error in report["errors"]))
            manifest["security"]["secrets_provider_verification"]["evidence"] = original_security_evidence

            original_product_evidence = manifest["product_certification"]["test_matrix"][1]["evidence"]
            manifest["product_certification"]["test_matrix"][1]["evidence"] = manifest["product_certification"]["test_matrix"][0]["evidence"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][2]["status"], "fail")
            manifest["product_certification"]["test_matrix"][1]["evidence"] = original_product_evidence

            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["score"], 100)

            for field_name in ("sbom", "signature", "signature_verified", "signature_verification"):
                removed = manifest["release"]["provider_bundle"].pop(field_name)
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                build_evidence_index(root, root / "evidence-index.json")
                report = assess_readiness(manifest_path, self.catalog)
                self.assertEqual(report["criteria"][1]["status"], "fail")
                manifest["release"]["provider_bundle"][field_name] = removed

            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["score"], 100)

            for section_name, field_name, replacement, criterion_index, error_text in (
                ("governance", "change_ticket", "CHG-9999", 0, "control.change_ticket must match governance.change_ticket"),
                ("support", "rpo_minutes", 15, 4, "support.rpo_minutes must match data_protection.rpo_minutes"),
                ("support", "rto_minutes", 90, 4, "support.rto_minutes must match data_protection.rto_minutes"),
                ("support", "on_call", "different-oncall", 6, "observability.on_call must match support.on_call"),
            ):
                original = manifest[section_name][field_name]
                manifest[section_name][field_name] = replacement
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                build_evidence_index(root, root / "evidence-index.json")
                report = assess_readiness(manifest_path, self.catalog)
                self.assertEqual(report["criteria"][criterion_index]["status"], "fail")
                self.assertTrue(any(error_text in error for error in report["errors"]))
                manifest[section_name][field_name] = original

            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["score"], 100)

            provider_subject = release_provenance["subject"].pop(1)
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            release_provenance["subject"].insert(1, provider_subject)
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            hosted_controls_subject = release_provenance["subject"].pop(2)
            (root / "provenance.json").write_text(
                json.dumps(release_provenance), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            release_provenance["subject"].insert(2, hosted_controls_subject)
            (root / "provenance.json").write_text(
                json.dumps(release_provenance), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")

            release_provenance["subject"][0]["digest"] = {"sha256": "0" * 64}
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            release_provenance["subject"][0]["digest"] = {"sha256": digest.split(":", 1)[1]}
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            execution_environment_provenance["subject"][0]["digest"] = {"sha256": "1" * 64}
            (root / "execution-environment-provenance.json").write_text(
                json.dumps(execution_environment_provenance), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            execution_environment_provenance["subject"][0]["digest"] = {
                "sha256": execution_environment_digest.split(":", 1)[1]
            }
            (root / "execution-environment-provenance.json").write_text(
                json.dumps(execution_environment_provenance), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")

            rollback_binding = manifest["recovery"].pop("rollback_artifact")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][7]["status"], "fail")
            self.assertTrue(any("recovery.rollback_artifact" in error for error in report["errors"]))
            manifest["recovery"]["rollback_artifact"] = rollback_binding

            manifest["product_certification"]["test_matrix"][0].pop("execution_environment_digest")
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("execution_environment_digest" in error for error in report["errors"]))
            manifest["product_certification"]["test_matrix"][0]["execution_environment_digest"] = execution_environment_digest

            (root / "release.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{}]}), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.spdx.json").write_text(
                json.dumps(_spdx_document("product-artifact")), encoding="utf-8"
            )
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            (root / "release.sig").write_bytes(b"")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.sig").write_bytes(b"signature-bytes\n")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")

            (root / "provenance.json").write_text("{}\n", encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][1]["status"], "fail")

            (root / "provenance.json").write_text(
                json.dumps(
                    _slsa_provenance(
                        [
                            {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                            {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                            {"name": "github-production-controls.json", "digest": {"sha256": github_audit_digest.split(":", 1)[1]}},
                        ]
                    )
                ),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")

            invalid_spdx_version = _spdx_document("product-artifact")
            invalid_spdx_version["spdxVersion"] = "2.3"
            (root / "release.spdx.json").write_text(
                json.dumps(invalid_spdx_version), encoding="utf-8"
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.spdx.json").write_text(
                json.dumps(_spdx_document("product-artifact")),
                encoding="utf-8",
            )

            missing_statement_type = _slsa_provenance(
                [
                    {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                    {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                    {"name": "github-production-controls.json", "digest": {"sha256": github_audit_digest.split(":", 1)[1]}},
                ]
            )
            missing_statement_type.pop("_type")
            (root / "provenance.json").write_text(
                json.dumps(missing_statement_type),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "provenance.json").write_text(
                json.dumps(
                    _slsa_provenance(
                        [
                            {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                            {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                            {"name": "github-production-controls.json", "digest": {"sha256": github_audit_digest.split(":", 1)[1]}},
                        ]
                    )
                ),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")

            manifest["product_certification"]["test_matrix"][0]["execution_environment"] = "staging"
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")

            manifest["product_certification"]["test_matrix"][0]["execution_environment"] = "qa"
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("execution_environment" in error for error in report["errors"]))
            manifest["product_certification"]["test_matrix"][0].pop("execution_environment")

            (root / "control.json").write_text('{"status":"pass"}\n', encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][0]["status"], "fail")
            write_evidence_payloads(manifest)

            manifest["product_certification"]["test_matrix"][0]["recorded_at"] = "2026-09-08 10:00:00"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][2]["status"], "fail")

            manifest["product_certification"]["test_matrix"][0]["recorded_at"] = recorded_at

            manifest["product_certification"]["test_matrix"][0]["recorded_at"] = future_recorded_at
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][2]["status"], "fail")
            self.assertTrue(
                any("recorded_at must not be future-dated" in error for error in report["errors"])
            )
            manifest["product_certification"]["test_matrix"][0]["recorded_at"] = recorded_at

            vulnerability_scan = manifest["security"]["vulnerability_scan"]
            vulnerability_scan["recorded_at"] = (
                approval_time - timedelta(days=8)
            ).isoformat().replace("+00:00", "Z")
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][5]["status"], "fail")
            self.assertTrue(
                any(
                    "security.vulnerability_scan.recorded_at exceeds the 7 days freshness window"
                    in error
                    for error in report["errors"]
                )
            )
            vulnerability_scan["recorded_at"] = recorded_at

            penetration_test = manifest["security"]["penetration_test"]
            penetration_test["recorded_at"] = (
                approval_time - timedelta(days=364)
            ).isoformat().replace("+00:00", "Z")
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            penetration_test["recorded_at"] = recorded_at

            backup = manifest["data_protection"]["backup"]
            backup["recorded_at"] = (
                approval_time - timedelta(minutes=70)
            ).isoformat().replace("+00:00", "Z")
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][4]["status"], "fail")
            self.assertTrue(
                any(
                    "data_protection.backup.recorded_at exceeds the 1 hour freshness window"
                    in error
                    for error in report["errors"]
                )
            )
            backup["recorded_at"] = recorded_at
            write_evidence_payloads(manifest)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")

            manifest["release"]["provider_bundle"]["digest"] = "sha256:not-a-digest"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("release.provider_bundle.digest" in error for error in report["errors"]))

            manifest["release"]["provider_bundle"]["digest"] = provider_bundle_digest
            manifest["release"]["provider_bundle"].pop("remote_digest")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("release.provider_bundle.remote_digest" in error for error in report["errors"]))

            manifest["release"]["provider_bundle"]["remote_digest"] = provider_bundle_digest

            manifest["data_protection"]["backup"]["environment"] = "staging"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][4]["status"], "fail")
            self.assertTrue(any("data_protection.backup.environment" in error for error in report["errors"]))
            manifest["data_protection"]["backup"]["environment"] = "production"

            manifest["product_certification"]["dependency_coverage"] = ["Python"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][2]["status"], "fail")
            self.assertTrue(any("product_certification.dependency_coverage is missing catalog coverage" in error for error in report["errors"]))

            manifest["product_certification"]["dependency_coverage"] = ["Python", "PostgreSQL", "Redis", "Tesseract", "OCRmyPDF", "Ghostscript", "Gotenberg", "Tika"]
            manifest["control"]["status"] = "pending"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["criteria"][0]["status"], "fail")
