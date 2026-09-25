"""Protect the first production apply as a distinct, one-use operation."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "deploy/ansible"
SITE = (ANSIBLE / "site.yml").read_text(encoding="utf-8")
CONTROLLER = (ANSIBLE / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8")
MANAGED = (ANSIBLE / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8")
KUBERNETES = (ANSIBLE / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")


class FirstApplyBootstrapTests(unittest.TestCase):
    def test_controller_requires_independent_authorization_and_nine_domains(self) -> None:
        self.assertLess(CONTROLLER.index("Verify the signed immutable source checkout"), CONTROLLER.index("Verify the separately approved first-apply authorization"))
        self.assertLess(CONTROLLER.index("Verify the controller-approved operational readiness manifest"), CONTROLLER.index("Verify the separately approved first-apply authorization"))
        self.assertIn("ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256", CONTROLLER)
        self.assertIn("archiveweaver_backup_verified | bool", CONTROLLER)
        self.assertIn("archiveweaver_solution_id == 'paperless-ngx'", CONTROLLER)
        self.assertIn("archiveweaver_runtime == 'rke2'", CONTROLLER)
        self.assertIn("score', 0) | int == 90", CONTROLLER)
        self.assertIn("['observability']", CONTROLLER)
        self.assertLess(CONTROLLER.index("Require nine independently proven pre-deployment readiness domains"), CONTROLLER.index("archiveweaver_controller_preflight_bootstrap_authorized: true"))
        self.assertIn("score', 0) | int == 100", CONTROLLER)
        self.assertIn("archiveweaver_controller_preflight_bootstrap_authorized", MANAGED)
        self.assertIn("archiveweaver_readiness_manifest_path == hostvars['localhost'].archiveweaver_readiness_manifest_path", MANAGED)

    def test_every_host_and_live_namespace_are_checked_before_mutation(self) -> None:
        self.assertLess(SITE.index("- name: Validate the pinned Ansible controller"), SITE.index("- name: Prove the first-use target is empty before any managed mutation"))
        self.assertLess(SITE.index("- name: Prove the first-use target is empty before any managed mutation"), SITE.index("- name: ArchiveWeaver enterprise deployment envelope"))
        first_use = SITE.split("- name: Prove the first-use target is empty before any managed mutation", 1)[1].split("- name: ArchiveWeaver enterprise deployment envelope", 1)[0]
        self.assertIn("hosts: archiveweaver_nodes", first_use)
        self.assertIn("any_errors_fatal: true", first_use)
        self.assertNotIn("serial:", first_use)
        for anchor in ("archiveweaver_release_record", "archiveweaver_data_root", "archiveweaver_log_root"):
            self.assertIn(anchor, first_use)
        self.assertIn("archiveweaver_bootstrap_anchor_stats.results | selectattr('stat.exists', 'equalto', true)", first_use)
        self.assertIn("archiveweaver_bootstrap_kubeconfig_stat.stat.checksum | default('') == archiveweaver_kubeconfig_sha256", first_use)
        self.assertIn("archiveweaver_bootstrap_namespace_result.stdout | trim == ''", first_use)
        self.assertLess(SITE.index("Verify the applied release and collect service evidence"), SITE.index("Seal ArchiveWeaver evidence after all managed hosts complete"))

    def test_bootstrap_restricts_every_rendered_resource_and_rechecks_before_apply(self) -> None:
        self.assertLess(KUBERNETES.index("Parse every rendered bootstrap Kubernetes object"), KUBERNETES.index("Apply the reviewed product Kustomize bundle"))
        self.assertLess(KUBERNETES.index("Confine every bootstrap resource to the dedicated namespace"), KUBERNETES.index("Apply the reviewed product Kustomize bundle"))
        self.assertLess(KUBERNETES.index("Recheck that the bootstrap namespace is still absent immediately before apply"), KUBERNETES.index("Apply the reviewed product Kustomize bundle"))
        self.assertLess(KUBERNETES.index("Atomically claim the absent bootstrap namespace"), KUBERNETES.index("Apply the reviewed product Kustomize bundle"))
        self.assertIn("archiveweaver_provider_bootstrap_namespace_uid", KUBERNETES)
        self.assertIn("Require the claimed bootstrap namespace to retain its identity", KUBERNETES)
        self.assertIn("archiveweaver_provider_bootstrap_objects | select('mapping') | list | length == archiveweaver_provider_bootstrap_objects | length", KUBERNETES)
        self.assertIn("selectattr('kind', 'equalto', 'Namespace') | list | length == 1", KUBERNETES)
        self.assertIn("item.get('metadata', {}).get('namespace') == archiveweaver_namespace", KUBERNETES)
        self.assertIn("archiveweaver_provider_bootstrap_namespace_result.stdout | trim == ''", KUBERNETES)
        for forbidden in ("ClusterRole", "CustomResourceDefinition", "PersistentVolume"):
            self.assertNotIn(f"('{forbidden}')", KUBERNETES)

    def test_apply_and_independent_verify_bind_images_to_signed_artifacts(self) -> None:
        coverage = (ANSIBLE / "roles/archiveweaver_provider/tasks/require-signed-image-coverage.yml").read_text(encoding="utf-8")
        self.assertIn("verify-provider-image-coverage.py", coverage)
        self.assertIn("archiveweaver_readiness_manifest_path", coverage)
        self.assertIn("ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", coverage)
        self.assertIn("is match('^[0-9a-f]{64}$')", coverage)
        self.assertIn("stdin: \"{{ archiveweaver_provider_image_coverage_model }}\"", coverage)
        self.assertIn("stdin_add_newline: false", coverage)
        self.assertIn("delegate_to: localhost", coverage)
        self.assertIn("archiveweaver_provider_image_coverage_result.rc == 0", coverage)
        for name, gate, mutation in (
            ("docker.yml", "Require signed image coverage before Compose apply", "Reconcile the declared Compose workload"),
            ("docker-swarm.yml", "Require signed image coverage before Swarm deploy", "Deploy the reviewed Swarm stack"),
            ("kubernetes.yml", "Require signed image coverage before Kubernetes apply", "Apply the reviewed product Kustomize bundle"),
        ):
            source = (ANSIBLE / "roles/archiveweaver_provider/tasks" / name).read_text(encoding="utf-8")
            self.assertLess(source.index(gate), source.index(mutation), name)
            self.assertIn("require-signed-image-coverage.yml", source, name)
            self.assertIn("when: not archiveweaver_preflight_is_staging_preview | default(false) | bool" if name != "kubernetes.yml" else "- not archiveweaver_preflight_is_staging_preview | default(false) | bool", source, name)
            if name in ("docker.yml", "docker-swarm.yml"):
                self.assertLess(source.index("Rehash the reviewed"), source.index(mutation), name)
                self.assertIn("stat.checksum | default('') == archiveweaver_product_stack_sha256", source, name)
        verify = (ANSIBLE / "roles/archiveweaver_provider/tasks/verify-bundle.yml").read_text(encoding="utf-8")
        for runtime in ("Compose", "Swarm", "Kubernetes"):
            self.assertIn(f"Require signed image coverage during {runtime} verification", verify)
        verify_record = (ANSIBLE / "roles/archiveweaver_verify/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("first_use_namespace:", verify_record)
        self.assertIn("archiveweaver_provider_bootstrap_namespace_uid", verify_record)


if __name__ == "__main__":
    unittest.main()
