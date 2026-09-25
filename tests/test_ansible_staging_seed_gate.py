"""Keep the first staging installation separate from production bootstrap."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "deploy/ansible"


class StagingSeedGateTests(unittest.TestCase):
    def test_controller_and_managed_hosts_require_staging_scope(self) -> None:
        controller = (ANSIBLE / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8")
        managed = (ANSIBLE / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256", controller)
        self.assertIn("ARCHIVEWEAVER_STAGING_INVENTORY_SHA256", controller)
        self.assertIn("verify-staging-seed-authorization.py", controller)
        self.assertIn("archiveweaver_evidence_environment == 'staging'", controller)
        self.assertIn("['control', 'release', 'governance', 'support']", controller)
        self.assertIn("archiveweaver_controller_preflight_staging_seed_authorized: true", controller)
        self.assertIn("archiveweaver_controller_preflight_staging_seed_authorized", managed)
        self.assertIn("archiveweaver_evidence_environment == 'staging'", managed)
        self.assertIn("['control', 'release', 'governance', 'support']", managed)

    def test_first_use_empty_target_and_namespace_claim_cover_staging(self) -> None:
        site = (ANSIBLE / "site.yml").read_text(encoding="utf-8")
        kubernetes = (ANSIBLE / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        verify = (ANSIBLE / "roles/archiveweaver_verify/tasks/main.yml").read_text(encoding="utf-8")
        evidence = (ANSIBLE / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("hostvars['localhost'].archiveweaver_controller_preflight_staging_seed_authorized", site)
        self.assertIn("archiveweaver_staging_seed_apply | default(false) | bool", site)
        self.assertLess(site.index("Prove the first-use target is empty"), site.index("ArchiveWeaver enterprise deployment envelope"))
        self.assertIn("archiveweaver_staging_seed_apply | default(false) | bool", kubernetes)
        self.assertLess(kubernetes.index("Atomically claim the absent bootstrap namespace"), kubernetes.index("Apply the reviewed product Kustomize bundle"))
        self.assertIn("staging_seed_first_apply", verify)
        self.assertIn("first_use_namespace", verify)
        self.assertIn("archiveweaver_staging_seed_apply | default(false) | bool", evidence)
        self.assertIn("archiveweaver_controller_preflight_staging_seed_active | bool", (ANSIBLE / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertLess(site.index("Verify the applied release and collect service evidence"), site.index("Seal ArchiveWeaver evidence"))

    def test_runner_and_workflow_keep_staging_authorization_distinct(self) -> None:
        runner = (ROOT / "scripts/run-ansible-operational.sh").read_text(encoding="utf-8")
        workflow = (ANSIBLE / "controller/workflow.yml").read_text(encoding="utf-8")
        self.assertIn("ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256", runner)
        self.assertIn("ARCHIVEWEAVER_STAGING_INVENTORY_SHA256", runner)
        self.assertIn('"${selected_inventory}" != "${ansible_root}/inventory/staging/hosts.yml"', runner)
        self.assertIn("id: staging-seed-approval", workflow)
        self.assertIn("id: staging-seed-apply", workflow)
        self.assertIn("archiveweaver_evidence_environment=staging", workflow)
        self.assertIn("ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256", workflow)
        self.assertIn("ARCHIVEWEAVER_STAGING_INVENTORY_SHA256", workflow)


if __name__ == "__main__":
    unittest.main()
