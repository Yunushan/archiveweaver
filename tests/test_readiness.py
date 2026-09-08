from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from archiveweaver.catalog import Catalog
from archiveweaver.evidence import build_evidence_index
from archiveweaver.readiness import assess_readiness


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
            build_evidence_index(root, root / "evidence-index.json")
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
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("not present in the catalog" in error for error in report["errors"]))

    def test_complete_evidence_manifest_scores_100(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "control.json", "release.json", "provenance.json", "release.spdx.json", "release.sig", "signature-verification.json", "execution-environment-provenance.json", "execution-environment.spdx.json", "execution-environment.sig", "execution-environment-signature-verification.json", "artifact.tar", "provider-bundle.tar", "provider-bundle-verification.json", "rollback-artifact.tar", "rollback.spdx.json", "rollback.sig", "rollback-signature-verification.json", "product.json",
                "product-dependencies.json", "product-smoke.json", "product-migration.json",
                "product-formats.json", "product-api.json", "failure.json", "failure-service.json",
                "failure-dependency.json", "failure-storage.json", "data.json",
                "backup.json", "restore.json", "fixity.json", "security.json", "scan.json",
                "pentest.json", "observe.json", "alert.json", "recovery.json", "rollback.json",
                "repair.json", "governance.json", "risk.json", "retention.json", "support.json", "runbook.md",
            ):
                (root / name).write_text("{}\n", encoding="utf-8")
            (root / "provenance.json").write_text(
                json.dumps(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "product-artifact"}],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
                ),
                encoding="utf-8",
            )
            (root / "release.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "packages": [{"name": "product-artifact"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "execution-environment-provenance.json").write_text(
                json.dumps(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "archiveweaver-execution-environment"}],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
                ),
                encoding="utf-8",
            )
            (root / "execution-environment.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "packages": [{"name": "archiveweaver-execution-environment"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "execution-environment.sig").write_bytes(b"execution-environment-signature\n")
            evidence = lambda name, status="pass", label="evidence": {"name": label, "status": status, "evidence": name, "solution": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "rke2", "os_id": "ubuntu-24.04", "release": "2026.09.1", "environment": "production", "execution_environment_digest": execution_environment_digest, "recorded_at": "2026-09-08T10:00:00Z", "operator": "ci", "fixture_set": "archiveweaver-fixtures-v1"}
            artifact = root / "artifact.tar"
            artifact.write_bytes(b"approved release artifact\n")
            digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
            provider_bundle = root / "provider-bundle.tar"
            provider_bundle.write_bytes(b"reviewed provider bundle\n")
            provider_bundle_digest = "sha256:" + hashlib.sha256(provider_bundle.read_bytes()).hexdigest()
            rollback_artifact = root / "rollback-artifact.tar"
            rollback_artifact.write_bytes(b"approved previous release artifact\n")
            rollback_digest = "sha256:" + hashlib.sha256(rollback_artifact.read_bytes()).hexdigest()
            (root / "rollback.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "previous-product-artifact"}]}),
                encoding="utf-8",
            )
            (root / "rollback.sig").write_bytes(b"rollback-signature\n")
            execution_environment_digest = "sha256:" + "c" * 64
            manifest = {
                "schema_version": 1,
                "service": {"solution_id": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "rke2", "os_id": "ubuntu-24.04", "environment": "production"},
                "evidence_index": "evidence-index.json",
                "control": {"status": "pass", "evidence": "control.json", "catalog_validated": True, "ci_green": True},
                "release": {"status": "pass", "evidence": "release.json", "version": "2026.09.1", "provenance": "provenance.json", "provenance_verified": True, "artifacts": [{"name": "product-artifact", "path": "artifact.tar", "digest": digest, "sbom": "release.spdx.json", "signature": "release.sig", "signature_verified": True, "signature_verification": evidence("signature-verification.json", label="signature")}], "provider_bundle": {"name": "provider-bundle", "path": "provider-bundle.tar", "digest": provider_bundle_digest, "remote_digest": provider_bundle_digest, "verification": evidence("provider-bundle-verification.json", label="provider-bundle")}},
                "product_certification": {
                    "status": "pass",
                    "evidence": "product.json",
                    "dependency_coverage": ["Python", "PostgreSQL", "Redis", "Tesseract", "OCRmyPDF", "Ghostscript", "Gotenberg", "Tika"],
                    "format_coverage": ["documents", "images", "email", "archives", "structured"],
                    "component_coverage": ["Django web", "Celery workers", "PostgreSQL", "Redis", "Tika/Gotenberg", "OCRmyPDF/Tesseract", "media storage"],
                    "test_matrix": [evidence(name, label=label) for name, label in [("product-dependencies.json", "dependencies"), ("product-smoke.json", "smoke"), ("product-migration.json", "migration"), ("product-formats.json", "formats"), ("product-api.json", "api")]],
                },
                "resilience": {"status": "pass", "evidence": "failure.json", "quorum_verified": True, "fencing_verified": True, "failure_tests": [evidence(name, label=label) for name, label in [("failure.json", "node"), ("failure-service.json", "service"), ("failure-dependency.json", "dependency"), ("failure-storage.json", "storage")]]},
                "data_protection": {"status": "pass", "evidence": "data.json", "rpo_minutes": 60, "rto_minutes": 240, "backup": {"status": "pass", "evidence": "backup.json", "immutable_copies": 2}, "restore_test": evidence("restore.json"), "fixity_test": evidence("fixity.json")},
                "security": {"status": "pass", "evidence": "security.json", "sbom_verified": True, "tls_verified": True, "secrets_provider": "vault", "vulnerability_scan": evidence("scan.json"), "penetration_test": evidence("pentest.json")},
                "observability": {"status": "pass", "evidence": "observe.json", "metrics": "prometheus", "alerts": "pager", "dashboards": "grafana", "on_call": "platform-oncall", "alert_delivery_test": evidence("alert.json", label="alert delivery")},
                "recovery": {"status": "pass", "evidence": "recovery.json", "rollback_release": "2026.09.0", "rollback_artifact_digest": rollback_digest, "rollback_artifact": {"name": "previous-product-artifact", "path": "rollback-artifact.tar", "digest": rollback_digest, "sbom": "rollback.spdx.json", "signature": "rollback.sig", "signature_verified": True, "signature_verification": evidence("rollback-signature-verification.json", label="rollback signature")}, "rollback_test": evidence("rollback.json"), "repair_test": evidence("repair.json")},
                "governance": {"status": "pass", "evidence": "governance.json", "change_ticket": "CHG-1234", "approved_by": "ops@example.org", "approved_at": "2026-09-08T10:00:00Z", "evidence_immutable": True, "evidence_access_logged": True, "evidence_retention_days": 2555, "retention_control": evidence("retention.json", label="retention"), "risk_review": evidence("risk.json")},
                "support": {"status": "pass", "evidence": "support.json", "service_owner": "Archive Platform", "on_call": "platform-oncall", "sla": "99.9%", "rpo_minutes": 60, "rto_minutes": 240, "runbooks": ["runbook.md"]},
            }
            for section_name in (
                "control", "release", "product_certification", "resilience", "data_protection",
                "security", "observability", "recovery", "governance", "support",
            ):
                manifest[section_name].update(evidence(manifest[section_name]["evidence"], label=section_name))
            manifest["data_protection"]["backup"].update(evidence("backup.json", label="backup"))
            manifest["release"]["artifacts"][0]["signature_verification"].update({"artifact_digest": digest, "verifier": "cosign"})
            manifest["release"]["provider_bundle"]["verification"].update({"artifact_digest": provider_bundle_digest, "remote_digest": provider_bundle_digest, "verifier": "ansible-provider-check"})
            manifest["recovery"]["rollback_artifact"]["signature_verification"].update({"artifact_digest": rollback_digest, "verifier": "cosign"})
            manifest["release"]["execution_environment"] = {
                "name": "archiveweaver-ee",
                "image": "registry.example/archiveweaver-ee@" + execution_environment_digest,
                "digest": execution_environment_digest,
                "provenance": "execution-environment-provenance.json",
                "provenance_verified": True,
                "sbom": "execution-environment.spdx.json",
                "signature": "execution-environment.sig",
                "signature_verified": True,
                "signature_verification": evidence("execution-environment-signature-verification.json", label="execution environment signature"),
            }
            manifest["release"]["execution_environment"]["signature_verification"].update({"artifact_digest": execution_environment_digest, "verifier": "cosign"})

            def write_evidence_payloads(value):
                if isinstance(value, dict):
                    if value.get("status") == "pass" and isinstance(value.get("evidence"), str):
                        (root / value["evidence"]).write_text(json.dumps(value), encoding="utf-8")
                    for child in value.values():
                        write_evidence_payloads(child)
                elif isinstance(value, list):
                    for child in value:
                        write_evidence_payloads(child)

            write_evidence_payloads(manifest)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["score"], 100)

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
            (root / "release.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "product-artifact"}]}), encoding="utf-8")
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
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "product-artifact"}],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
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

            manifest["product_certification"]["test_matrix"][0]["recorded_at"] = "2026-09-08T10:00:00Z"

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
