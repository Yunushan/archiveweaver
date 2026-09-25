from __future__ import annotations

import copy
import unittest
from pathlib import Path

from archiveweaver.readiness import _deployment_target_complete, _deployment_target_errors


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "deploy" / "ansible"


class DeploymentTargetBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = {
            "kube_context": "approved-rke2-context",
            "kubeconfig_sha256": "a" * 64,
            "inventory_sha256": "b" * 64,
            "namespace": "archiveweaver",
            "kube_system_namespace_uid": "d3fabefa-c024-4588-88b1-c38095fd7740",
            "application_namespace_uid": "1e7d7261-239a-447e-9461-a8c3f4115196",
        }
        self.manifest = {
            "service": {
                "solution_id": "paperless-ngx",
                "runtime": "ansible",
                "underlying_runtime": "rke2",
                "environment": "production",
            },
            "deployment_target": copy.deepcopy(self.target),
            "observability": {"status": "pass"},
        }

    def test_complete_target_required_for_production_100(self) -> None:
        self.assertEqual(_deployment_target_errors(self.manifest), [])
        self.assertTrue(_deployment_target_complete(self.manifest))
        del self.manifest["deployment_target"]
        self.assertFalse(_deployment_target_complete(self.manifest))
        self.assertIn("required", _deployment_target_errors(self.manifest)[0])

    def test_rejects_placeholder_or_replayed_namespace_uids(self) -> None:
        for field, replacement in (
            ("kube_system_namespace_uid", "REPLACE_WITH_UID"),
            ("application_namespace_uid", "00000000-0000-0000-0000-000000000000"),
            ("application_namespace_uid", self.target["kube_system_namespace_uid"]),
        ):
            with self.subTest(field=field, replacement=replacement):
                candidate = copy.deepcopy(self.manifest)
                candidate["deployment_target"][field] = replacement
                self.assertFalse(_deployment_target_complete(candidate))
                self.assertTrue(_deployment_target_errors(candidate))

    def test_rejects_malformed_target_shape_and_fields(self) -> None:
        malformed = (
            ("deployment_target", []),
            ("deployment_target.kube_context", None),
            ("deployment_target.kube_context", "REPLACE_WITH_CONTEXT"),
            ("deployment_target.kube_context", "context with spaces"),
            ("deployment_target.kubeconfig_sha256", None),
            ("deployment_target.kubeconfig_sha256", "x" * 64),
            ("deployment_target.inventory_sha256", "short"),
            ("deployment_target.namespace", None),
            ("deployment_target.namespace", "REPLACE_WITH_NAMESPACE"),
            ("deployment_target.namespace", "Upper_Case"),
        )
        for field, replacement in malformed:
            with self.subTest(field=field, replacement=replacement):
                candidate = copy.deepcopy(self.manifest)
                if field == "deployment_target":
                    candidate["deployment_target"] = replacement
                else:
                    candidate["deployment_target"][field.removeprefix("deployment_target.")] = replacement
                self.assertFalse(_deployment_target_complete(candidate))
                self.assertTrue(
                    any(field in error for error in _deployment_target_errors(candidate))
                )
        for change in ("missing", "extra"):
            with self.subTest(shape=change):
                candidate = copy.deepcopy(self.manifest)
                if change == "missing":
                    del candidate["deployment_target"]["kube_context"]
                else:
                    candidate["deployment_target"]["unapproved"] = "value"
                self.assertFalse(_deployment_target_complete(candidate))
                self.assertTrue(
                    any("exactly the six" in error for error in _deployment_target_errors(candidate))
                )

    def test_first_use_allows_absent_application_uid_before_observability(self) -> None:
        self.manifest["observability"]["status"] = "pending"
        self.manifest["deployment_target"]["application_namespace_uid"] = None
        self.manifest["bootstrap_authorization"] = {
            field: self.target[field]
            for field in ("kube_context", "kubeconfig_sha256", "inventory_sha256", "namespace")
        }
        self.assertEqual(_deployment_target_errors(self.manifest), [])
        self.assertFalse(_deployment_target_complete(self.manifest))
        self.manifest["observability"]["status"] = "pass"
        self.assertIn("application_namespace_uid", " ".join(_deployment_target_errors(self.manifest)))

    def test_bootstrap_target_must_match_separate_authorization(self) -> None:
        self.manifest["observability"]["status"] = "pending"
        self.manifest["deployment_target"]["application_namespace_uid"] = None
        self.manifest["bootstrap_authorization"] = {
            field: self.target[field]
            for field in ("kube_context", "kubeconfig_sha256", "inventory_sha256", "namespace")
        }
        self.manifest["deployment_target"]["kube_context"] = "different-context"
        self.assertTrue(
            any("bootstrap_authorization.kube_context" in error
                for error in _deployment_target_errors(self.manifest))
        )

    def test_controller_queries_approved_live_target_before_100_gate(self) -> None:
        preflight = (
            ANSIBLE / "roles/archiveweaver_controller_preflight/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertLess(
            preflight.index("Bind ordinary production apply and verify to both live Namespace UIDs"),
            preflight.index("Require applied workflows to match the signed readiness identity"),
        )
        for expected in (
            "ARCHIVEWEAVER_PRODUCTION_INVENTORY_SHA256",
            "archiveweaver_controller_preflight_target_inventory_stat.stat.checksum",
            "archiveweaver_controller_preflight_target_kubeconfig_stat.stat.checksum",
            "'get', 'namespace', 'kube-system'",
            "'get', 'namespace', archiveweaver_namespace",
            "archiveweaver_controller_preflight_target_binding.kube_system_namespace_uid",
            "archiveweaver_controller_preflight_target_binding.application_namespace_uid",
        ):
            self.assertIn(expected, preflight)
        self.assertIn("archiveweaver_controller_preflight_readiness_gate_active | bool", preflight)

    def test_generated_records_use_only_the_controller_verified_target(self) -> None:
        for role in (
            "archiveweaver_certification",
            "archiveweaver_failure",
            "archiveweaver_restore",
            "archiveweaver_rollback",
            "archiveweaver_repair",
            "archiveweaver_verify",
        ):
            with self.subTest(role=role):
                content = (ANSIBLE / f"roles/{role}/tasks/main.yml").read_text(encoding="utf-8")
                self.assertIn(
                    "hostvars['localhost'].archiveweaver_controller_preflight_readiness_identity.get('deployment_target', {})",
                    content,
                )


if __name__ == "__main__":
    unittest.main()
