"""Guard the narrow staging recovery evidence path in the controller contract."""

from __future__ import annotations

import copy
import runpy
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "deploy/ansible"
WORKFLOW = ANSIBLE / "controller/workflow.yml"
CONTROLLER_PREFLIGHT = ANSIBLE / "roles/archiveweaver_controller_preflight/tasks/main.yml"
MANAGED_PREFLIGHT = ANSIBLE / "roles/archiveweaver_preflight/tasks/main.yml"
VERIFY = ANSIBLE / "roles/archiveweaver_verify/tasks/main.yml"


def named_task(path: Path, name: str) -> dict:
    tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
    return next(task for task in tasks if task.get("name") == name)


class StagingRecoveryDrillTests(unittest.TestCase):
    def test_controller_exception_keeps_source_and_manifest_checks(self) -> None:
        guard = named_task(CONTROLLER_PREFLIGHT, "Confine recovery drills to the approved staging inventory and target")
        assertions = " ".join(guard["ansible.builtin.assert"]["that"])
        for required in (
            "ansible_inventory_sources == ['inventory/staging/hosts.yml']",
            "archiveweaver_environment == 'staging'",
            "archiveweaver_evidence_environment == 'production'",
            "not (ansible_check_mode | bool)",
            "not (archiveweaver_apply | default(false) | bool)",
            "archiveweaver_rollback_environment | default('') == 'staging'",
        ):
            self.assertIn(required, assertions)
        readiness = named_task(CONTROLLER_PREFLIGHT, "Determine whether the final readiness gate applies")
        self.assertIn(
            "not (archiveweaver_controller_preflight_recovery_drill_active | bool)",
            readiness["ansible.builtin.set_fact"]["archiveweaver_controller_preflight_readiness_gate_active"],
        )
        source = named_task(CONTROLLER_PREFLIGHT, "Determine whether immutable source verification applies")
        self.assertNotIn(
            "recovery_drill",
            source["ansible.builtin.set_fact"]["archiveweaver_controller_preflight_source_gate_active"],
        )
        for name in (
            "Verify the signed immutable source checkout",
            "Require the approved readiness manifest bytes",
            "Bind every applied workflow to the approved readiness identity",
            "Require the controller image identity to match the job binding",
        ):
            self.assertEqual(
                named_task(CONTROLLER_PREFLIGHT, name)["when"],
                "archiveweaver_controller_preflight_source_gate_active | bool",
            )

    def test_managed_exception_keeps_provider_and_image_identity(self) -> None:
        guard = named_task(MANAGED_PREFLIGHT, "Confine managed recovery drills to the approved staging hosts")
        assertions = " ".join(guard["ansible.builtin.assert"]["that"])
        self.assertIn("inventory_file in ['inventory/staging/hosts.yml', archiveweaver_bundle_root ~ '/inventory/staging/hosts.yml']", assertions)
        self.assertIn("archiveweaver_evidence_environment == 'production'", assertions)
        for name in (
            "Verify the repository readiness score on the controller",
            "Require a 100-point readiness result before mutation",
        ):
            self.assertIn(
                "not archiveweaver_preflight_recovery_drill_active | bool",
                named_task(MANAGED_PREFLIGHT, name)["when"],
            )
        for name in (
            "Bind a staging recovery drill to the protected manifest and execution environment",
            "Bind a Kubernetes staging recovery drill to the protected provider bundle",
            "Bind a raw or Quadlet staging recovery drill to the protected provider bundle",
            "Bind staging recovery drill execution to the controller-approved image",
        ):
            task = named_task(MANAGED_PREFLIGHT, name)
            self.assertIn("archiveweaver_preflight_recovery_drill_active | bool", task["when"])
            self.assertIn(
                "archiveweaver_controller_preflight_readiness_identity",
                " ".join(task["ansible.builtin.assert"]["that"]),
            )

    def test_auxiliary_staging_verification_cannot_claim_production_target(self) -> None:
        evidence = named_task(VERIFY, "Build a redacted per-host evidence record")
        environment = evidence["ansible.builtin.set_fact"]["archiveweaver_verify_evidence"]["environment"]
        self.assertIn("archiveweaver_environment if (archiveweaver_recovery_drill", environment)
        self.assertIn("else archiveweaver_evidence_environment", environment)

    def test_contract_rejects_drift_to_production_or_unpinned_target(self) -> None:
        contract = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        validate = runpy.run_path(str(ROOT / "scripts/validate-controller-contract.py"))["validate"]
        self.assertEqual(validate(contract), [])
        for workflow_id, original, replacement in (
            ("staging-repair-drill", "inventory/staging/hosts.yml", "inventory/production/hosts.yml"),
            ("staging-repair-drill", "archiveweaver_recovery_drill=true", "archiveweaver_recovery_drill=false"),
            ("staging-repair-drill", "archiveweaver_evidence_environment=production", "archiveweaver_evidence_environment=staging"),
            ("staging-rollback-drill", "archiveweaver_rollback_environment=staging", "archiveweaver_rollback_environment=production"),
        ):
            with self.subTest(workflow_id=workflow_id, original=original):
                changed = copy.deepcopy(contract)
                item = next(item for item in changed["workflow"] if item["id"] == workflow_id)
                item["command"] = item["command"].replace(original, replacement)
                self.assertTrue(validate(changed))


if __name__ == "__main__":
    unittest.main()
