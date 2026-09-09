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
                "control.json", "release.json", "provenance.json", "release.spdx.json", "release.sig", "signature-verification.json", "execution-environment-provenance.json", "execution-environment.spdx.json", "execution-environment.sig", "execution-environment-signature-verification.json", "artifact.tar", "provider-bundle.tar", "provider-bundle.spdx.json", "provider-bundle.sig", "provider-bundle-signature-verification.json", "provider-bundle-verification.json", "rollback-artifact.tar", "rollback.spdx.json", "rollback.sig", "rollback-signature-verification.json", "product.json", "resilience.json",
                "product-dependencies.json", "product-smoke.json", "product-migration.json",
                "product-formats.json", "product-api.json", "failure.json", "failure-service.json",
                "failure-dependency.json", "failure-storage.json", "data.json",
                "backup.json", "restore.json", "fixity.json", "security.json", "security-sbom.json", "tls.json",
                "secrets-provider.json", "scan.json", "pentest.json", "observe.json", "metrics.json", "alerts.json",
                "dashboards.json", "on-call.json", "alert.json", "recovery.json", "rollback.json", "repair.json",
                "governance.json", "risk.json", "retention.json", "support.json", "service-owner.json", "support-on-call.json",
                "sla.json", "runbook.md",
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
                        "subject": [{"name": "archiveweaver-ee"}],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
                ),
                encoding="utf-8",
            )
            (root / "execution-environment.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "packages": [{"name": "archiveweaver-ee"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "execution-environment.sig").write_bytes(b"execution-environment-signature\n")
            evidence = lambda name, status="pass", label="evidence": {"name": label, "status": status, "evidence": name, "solution": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "rke2", "os_id": "ubuntu-24.04", "release": "2026.09.1", "environment": "production", "execution_environment_digest": execution_environment_digest, "recorded_at": "2026-09-08T10:00:00Z", "operator": "ci", "fixture_set": "archiveweaver-fixtures-v1"}
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
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "provider-bundle"}]}),
                encoding="utf-8",
            )
            (root / "provider-bundle.sig").write_bytes(b"provider-bundle-signature\n")
            release_provenance["subject"].append(
                {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}}
            )
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            rollback_artifact = root / "rollback-artifact.tar"
            rollback_artifact.write_bytes(b"approved previous release artifact\n")
            rollback_digest = "sha256:" + hashlib.sha256(rollback_artifact.read_bytes()).hexdigest()
            (root / "rollback.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "previous-product-artifact"}]}),
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
                "evidence_index": "evidence-index.json",
                "control": {"status": "pass", "evidence": "control.json", "catalog_validated": True, "ci_green": True, "change_ticket": "CHG-1234"},
                "release": {"status": "pass", "evidence": "release.json", "version": "2026.09.1", "provenance": "provenance.json", "provenance_verified": True, "artifacts": [{"name": "product-artifact", "path": "artifact.tar", "digest": digest, "sbom": "release.spdx.json", "signature": "release.sig", "signature_verified": True, "signature_verification": evidence("signature-verification.json", label="signature")}], "provider_bundle": {"name": "provider-bundle", "path": "provider-bundle.tar", "digest": provider_bundle_digest, "remote_digest": provider_bundle_digest, "sbom": "provider-bundle.spdx.json", "signature": "provider-bundle.sig", "signature_verified": True, "signature_verification": evidence("provider-bundle-signature-verification.json", label="provider bundle signature"), "verification": evidence("provider-bundle-verification.json", label="provider-bundle")}},
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
                "recovery": {"status": "pass", "evidence": "recovery.json", "rollback_release": "2026.09.0", "rollback_artifact_digest": rollback_digest, "rollback_artifact": {"name": "previous-product-artifact", "path": "rollback-artifact.tar", "digest": rollback_digest, "sbom": "rollback.spdx.json", "signature": "rollback.sig", "signature_verified": True, "signature_verification": evidence("rollback-signature-verification.json", label="rollback signature")}, "rollback_test": evidence("rollback.json"), "repair_test": evidence("repair.json")},
                "governance": {"status": "pass", "evidence": "governance.json", "change_ticket": "CHG-1234", "approved_by": "ops@example.org", "approved_at": "2026-09-08T10:00:00Z", "evidence_immutable": True, "evidence_access_logged": True, "evidence_retention_days": 2555, "retention_control": evidence("retention.json", label="retention"), "risk_review": evidence("risk.json")},
                "support": {"status": "pass", "evidence": "support.json", "service_owner": "Archive Platform", "on_call": "platform-oncall", "sla": "99.9%", "service_owner_verification": evidence("service-owner.json", label="service owner"), "on_call_verification": evidence("support-on-call.json", label="support on-call"), "sla_verification": evidence("sla.json", label="SLA"), "rpo_minutes": 60, "rto_minutes": 240, "runbooks": ["runbook.md"]},
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

            original_release_sbom = (root / "release.spdx.json").read_text(encoding="utf-8")
            (root / "release.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "unrelated-artifact"}]}),
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

            provider_subject = release_provenance["subject"].pop()
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            release_provenance["subject"].append(provider_subject)
            (root / "provenance.json").write_text(json.dumps(release_provenance), encoding="utf-8")
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
                        "subject": [
                            {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                            {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                        ],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
                ),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["status"], "pass")

            (root / "release.spdx.json").write_text(
                json.dumps({"spdxVersion": "2.3", "packages": [{"name": "product-artifact"}]}),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "release.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "product-artifact"}]}),
                encoding="utf-8",
            )

            (root / "provenance.json").write_text(
                json.dumps(
                    {
                        "subject": [
                            {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                            {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                        ],
                        "predicateType": "https://slsa.dev/provenance/v1",
                    }
                ),
                encoding="utf-8",
            )
            build_evidence_index(root, root / "evidence-index.json")
            report = assess_readiness(manifest_path, self.catalog)
            self.assertEqual(report["criteria"][1]["status"], "fail")
            (root / "provenance.json").write_text(
                json.dumps(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [
                            {"name": "product-artifact", "digest": {"sha256": digest.split(":", 1)[1]}},
                            {"name": "provider-bundle", "digest": {"sha256": provider_bundle_digest.split(":", 1)[1]}},
                        ],
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
