from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_ROOT = ROOT / "deploy" / "ansible"


class AnsibleEditionTests(unittest.TestCase):
    def test_required_ansible_project_files_exist(self) -> None:
        for relative in (
            "ansible.cfg",
            ".ansible-lint",
            "requirements.txt",
            "requirements.yml",
            "release-manifest.example.json",
            "site.yml",
            "verify.yml",
            "repair.yml",
            "restore-drill.yml",
            "failure-drill.yml",
            "rollback.yml",
            "product-certification.yml",
            "controller/workflow.yml",
            "controller/README.md",
            "execution-environment/Containerfile",
            "execution-environment/requirements.txt",
            "execution-environment/README.md",
            "../../scripts/validate-ansible.sh",
            "inventory/production/hosts.yml.example",
            "inventory/staging/hosts.yml.example",
            "inventory/restore/hosts.yml.example",
            "group_vars/all/main.yml",
            "group_vars/all/vault.yml.example",
            "roles/archiveweaver_preflight/tasks/main.yml",
            "roles/archiveweaver_controller_preflight/tasks/main.yml",
            "roles/archiveweaver_host/tasks/main.yml",
            "roles/archiveweaver_provider/tasks/main.yml",
            "roles/archiveweaver_provider/tasks/verify-bundle.yml",
            "roles/archiveweaver_repair/tasks/main.yml",
            "roles/archiveweaver_restore/tasks/main.yml",
            "roles/archiveweaver_failure/tasks/main.yml",
            "roles/archiveweaver_rollback/tasks/main.yml",
            "roles/archiveweaver_observe/tasks/main.yml",
            "roles/archiveweaver_verify/tasks/main.yml",
            "roles/archiveweaver_evidence/tasks/main.yml",
            "roles/archiveweaver_certification/tasks/main.yml",
        ):
            self.assertTrue((ANSIBLE_ROOT / relative).is_file(), relative)

    def test_execution_environment_rejects_mutable_base_image_tags(self) -> None:
        containerfile = (ANSIBLE_ROOT / "execution-environment/Containerfile").read_text(encoding="utf-8")
        self.assertIn("ARG BASE_IMAGE", containerfile)
        self.assertIn("@sha256:[0-9a-f]{64}", containerfile)
        self.assertIn("BASE_IMAGE must be an OCI reference with a 64-character SHA-256 digest", containerfile)

    def test_apply_and_repair_defaults_are_fail_closed(self) -> None:
        main_vars = (ANSIBLE_ROOT / "group_vars/all/main.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_apply: false", main_vars)
        self.assertIn("archiveweaver_repair_apply: false", main_vars)
        self.assertIn("archiveweaver_staging_preview: false", main_vars)
        self.assertIn("archiveweaver_backup_verified: false", main_vars)
        self.assertIn("archiveweaver_product_stack_ready: false", main_vars)
        self.assertIn('archiveweaver_bundle_root:', main_vars)
        self.assertIn('archiveweaver_readiness_manifest_path: "{{ archiveweaver_bundle_root }}/release-manifest.json"', main_vars)
        self.assertIn("archiveweaver_runtime: rke2", main_vars)
        self.assertIn("archiveweaver_environment: production", main_vars)
        self.assertIn("archiveweaver_observe_enabled: false", main_vars)
        self.assertIn("archiveweaver_external_consensus_ready: false", main_vars)
        self.assertIn('archiveweaver_ansible_core_version: "2.21.0"', main_vars)
        self.assertIn('archiveweaver_execution_environment_digest: ""', main_vars)
        self.assertIn('archiveweaver_readiness_pythonpath: "{{ archiveweaver_bundle_root }}/../../src"', main_vars)
        self.assertIn('archiveweaver_product_stack_sha256: ""', main_vars)
        self.assertIn('archiveweaver_kustomize_bundle_sha256: ""', main_vars)
        self.assertIn('archiveweaver_provider_bundle_sha256: ""', main_vars)
        self.assertIn("Verify the repository readiness score on the controller", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Require a regular controller readiness manifest", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('runtime') == 'ansible'", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('underlying_runtime') == archiveweaver_runtime", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('environment') == archiveweaver_environment", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Verify the pinned Ansible Core on the controller", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Seal the controller evidence root with a SHA-256 index", (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Verify the sealed controller evidence index", (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("archiveweaver_operator: \"\"", main_vars)
        self.assertIn("archiveweaver_fixture_set: \"\"", main_vars)
        self.assertIn("archiveweaver_evidence_environment: production", main_vars)
        self.assertIn("archiveweaver_evidence_publish_enabled: false", main_vars)
        self.assertIn("archiveweaver_evidence_publish_command: []", main_vars)
        self.assertIn("archiveweaver_evidence_verify_command: []", main_vars)
        self.assertIn("archiveweaver_evidence_retention_days: 0", main_vars)

    def test_inventory_defines_restore_and_runtime_group_relationships(self) -> None:
        inventory = (ANSIBLE_ROOT / "inventory/production/hosts.yml.example").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_failure_domain: zone-a", inventory)
        self.assertIn("  children:\n    archiveweaver_nodes:\n      children:", inventory)
        staging_inventory = (ANSIBLE_ROOT / "inventory/staging/hosts.yml.example").read_text(encoding="utf-8")
        self.assertIn("    archiveweaver_failure:\n      children:\n        archiveweaver_nodes:", staging_inventory)
        self.assertIn("    archiveweaver_certification:\n      children:\n        archiveweaver_app:", staging_inventory)
        self.assertIn("archiveweaver_environment: staging", staging_inventory)
        self.assertIn("archiveweaver_nodes: \"1\"", staging_inventory)
        restore_inventory = (ANSIBLE_ROOT / "inventory/restore/hosts.yml.example").read_text(encoding="utf-8")
        self.assertIn("    archiveweaver_restore:\n      hosts:", restore_inventory)

    def test_preflight_enforces_consensus_and_fencing_invariants(self) -> None:
        preflight = (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require an odd control-plane shape for consensus runtimes", preflight)
        self.assertIn("Require an external quorum design for two-node consensus", preflight)
        self.assertIn("Require fencing before any Pacemaker mutation", preflight)
        self.assertIn("Require inventory cardinality for the declared topology", preflight)
        self.assertIn("Require explicit design approval for a conditional multi-node provider", preflight)
        self.assertIn("archiveweaver_topology_design_approved", preflight)
        self.assertIn("Require explicit approval for a single-node consensus production topology", preflight)
        self.assertIn("archiveweaver_single_node_production_approved", preflight)
        self.assertIn("Require explicit role groups before a production mutation", preflight)
        self.assertIn("Require distinct control-plane failure domains", preflight)
        self.assertIn("Require a failure-domain label for every managed node", preflight)
        self.assertIn("groups['archiveweaver_control'] | length > 0", preflight)
        self.assertIn("groups['archiveweaver_app'] | length > 0", preflight)
        self.assertIn("archiveweaver_run_verification | bool", preflight)
        self.assertIn("Derive the catalog OS identifier from managed-host facts", preflight)
        self.assertIn("Require the managed host to match the declared catalog OS", preflight)
        self.assertIn("Inspect managed filesystem anchors before any host mutation", preflight)
        self.assertIn("Reject symlinked managed filesystem anchors", preflight)
        self.assertIn("archiveweaver_namespace is match", preflight)
        self.assertIn("archiveweaver_app_port | int < 65536", preflight)
        self.assertIn("archiveweaver_data_root is match('^/srv/archiveweaver/' ~ archiveweaver_solution_id", preflight)
        self.assertIn("archiveweaver_log_root is match('^/var/log/archiveweaver/' ~ archiveweaver_solution_id", preflight)
        self.assertIn("archiveweaver_release_record is match('^/etc/archiveweaver/' ~ archiveweaver_solution_id", preflight)
        self.assertIn("archiveweaver_approval_ticket is not search", preflight)
        self.assertIn("archiveweaver_kubeconfig is string", preflight)
        self.assertIn("Require an explicit kubeconfig for Kubernetes-family operations", preflight)
        self.assertIn("Require a private, regular kubeconfig on the first control host", preflight)
        self.assertIn("archiveweaver_kustomize_path is not match('/$')", preflight)
        self.assertIn("archiveweaver_compose_path is match('^/etc/archiveweaver/' ~ archiveweaver_solution_id", preflight)
        self.assertIn("archiveweaver_kustomize_path is match('^/etc/archiveweaver/' ~ archiveweaver_solution_id", preflight)
        self.assertIn("archiveweaver_readiness_manifest_path is match('^' ~ (archiveweaver_bundle_root | regex_escape)", preflight)
        self.assertIn("archiveweaver_evidence_root is match('^' ~ (archiveweaver_bundle_root | regex_escape) ~ '/evidence(/|$)')", preflight)
        self.assertIn("archiveweaver_bundle_root == ((ansible_config_file | default(playbook_dir ~ '/ansible.cfg', true)) | regex_replace('/[^/]+$', ''))", preflight)
        self.assertIn("archiveweaver_health_url | length == 0 or archiveweaver_health_url is match('^https://[^/", preflight)
        self.assertIn("archiveweaver_health_url is match('^https://[^/", (ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("archiveweaver_health_validate_certs | bool", preflight)
        self.assertIn("Derive the narrowly scoped staging preview mode", preflight)
        self.assertIn("not archiveweaver_is_staging_preview | bool", preflight)
        self.assertIn("Bind the reviewed Compose or Swarm digest to readiness", preflight)
        self.assertIn("Bind the reviewed Kustomize digest to readiness", preflight)
        self.assertIn("provider_bundle.remote_digest", preflight)
        self.assertIn("Bind the reviewed raw or Quadlet digest to readiness", preflight)
        self.assertIn("Require a health endpoint for non-systemd verification", preflight)
        self.assertIn("archiveweaver_health_url is not search('[@?#$%&;]')", preflight)
        self.assertIn("archiveweaver_health_url is not search('\\\\')", preflight)
        self.assertIn("Bind standard-playbook evidence to its target environment", preflight)
        self.assertIn("archiveweaver_provider_probe_hosts", preflight)
        observe = (ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("^[1-9][0-9]*(s|min|h|d)$", observe)
        self.assertIn("archiveweaver_health_url is not search('[@?#$%&;]')", observe)
        self.assertIn("archiveweaver_health_url is not search('\\\\')", observe)
        self.assertIn("Reject colliding managed-host evidence filenames", preflight)
        self.assertIn("archiveweaver_ansible_core_version is match", preflight)
        self.assertIn("Bind the live execution environment to the reviewed readiness manifest", preflight)
        self.assertIn("ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST", preflight)
        controller_preflight = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require the pinned Ansible Core execution environment", controller_preflight)
        self.assertIn("Require an immutable execution-environment digest for applied workflows", controller_preflight)
        self.assertIn("ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST", controller_preflight)
        self.assertIn("Determine whether the final readiness gate applies", controller_preflight)
        self.assertIn("archiveweaver_controller_readiness_gate_active", controller_preflight)
        self.assertIn("Validate the controller readiness manifest boundary", controller_preflight)
        self.assertIn("Require a regular controller readiness manifest", controller_preflight)
        self.assertIn("ansible_config_file | default(playbook_dir ~ '/ansible.cfg', true)", controller_preflight)
        for playbook in ("product-certification.yml", "restore-drill.yml", "failure-drill.yml", "rollback.yml"):
            self.assertIn("archiveweaver_controller_preflight", (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8"))
        self.assertGreaterEqual((ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8").count("diff: false"), 3)
        failure = (ANSIBLE_ROOT / "roles/archiveweaver_failure/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("'node' in (archiveweaver_failure_tests | map(attribute='name') | list)", failure)
        self.assertIn("execution_environment_digest", failure)
        docker = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker.yml").read_text(encoding="utf-8")
        self.assertIn("Require a staged product Compose stack", docker)
        self.assertIn("Require the reviewed Compose stack digest", docker)
        self.assertNotIn("Render the reviewed Compose envelope", docker)
        swarm = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker-swarm.yml").read_text(encoding="utf-8")
        self.assertIn("Require the reviewed Swarm stack digest", swarm)
        raw = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/raw.yml").read_text(encoding="utf-8")
        self.assertIn("not ansible_check_mode | bool", raw)
        self.assertIn("archiveweaver_exec_start is not search('%')", raw)
        quadlet = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/podman-quadlet.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_image is match('^[A-Za-z0-9]", quadlet)
        self.assertIn("immutable image digest", quadlet)
        self.assertIn("not ansible_check_mode | bool", quadlet)
        self.assertGreaterEqual(quadlet.count("notify: Restart ArchiveWeaver service"), 3)
        self.assertGreaterEqual(quadlet.count("diff: false"), 3)
        kubernetes = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        self.assertIn("Require a staged product Kustomize bundle", kubernetes)
        self.assertIn("Require the reviewed Kustomize bundle digest", kubernetes)
        self.assertIn("replace(archiveweaver_kustomize_path", kubernetes)
        self.assertIn("Reject symlinks inside the staged product Kustomize bundle", kubernetes)
        self.assertIn("Render the staged product Kustomize bundle read-only", kubernetes)
        verify_bundle = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/verify-bundle.yml").read_text(encoding="utf-8")
        self.assertIn("Require the verified Compose bundle to match its release digest", verify_bundle)
        self.assertIn("Require the verified Kustomize bundle to match its release digest", verify_bundle)
        self.assertIn("replace(archiveweaver_kustomize_path", verify_bundle)
        self.assertIn("Reject symlinks inside the verified Kustomize bundle", verify_bundle)
        self.assertIn("Require the verified raw provider unit to match its release digest", verify_bundle)
        self.assertIn("Require the verified Quadlet provider to match its release digest", verify_bundle)
        repair = (ANSIBLE_ROOT / "roles/archiveweaver_repair/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Build redacted repair evidence", repair)
        self.assertIn("execution_environment", repair)
        self.assertIn("no_log: true", repair)
        self.assertIn("Require the reviewed Compose repair bundle", repair)
        self.assertIn("Require the reviewed Swarm repair bundle", repair)
        self.assertIn("Reconcile the declared Compose workload", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker.yml").read_text(encoding="utf-8"))
        self.assertIn("Deploy the reviewed Swarm stack", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker-swarm.yml").read_text(encoding="utf-8"))
        self.assertIn("Apply the reviewed product Kustomize bundle", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8"))
        self.assertIn("inventory_hostname == groups['archiveweaver_app'][0]", repair)
        self.assertIn("inventory_hostname == groups['archiveweaver_control'][0]", repair)
        certification = (ANSIBLE_ROOT / "roles/archiveweaver_certification/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require the complete reviewed product test matrix", certification)
        self.assertIn("Require real certification identity for an applied matrix", certification)
        self.assertIn("Refuse to execute certification hooks in check mode", certification)
        self.assertIn("Run the reviewed product certification hooks", certification)
        self.assertIn("'underlying_runtime': archiveweaver_runtime", certification)
        self.assertIn("'execution_environment_digest': archiveweaver_execution_environment_digest", certification)
        self.assertIn("inventory_hostname == groups['archiveweaver_certification'][0]", certification)
        verify = (ANSIBLE_ROOT / "roles/archiveweaver_verify/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("host-verification-", verify)
        self.assertIn("archiveweaver_operator", verify)
        self.assertIn("execution_environment", verify)
        self.assertIn("execution_environment_digest", verify)
        self.assertIn("follow_redirects: none", verify)
        self.assertIn("status_code: [200, 201, 202, 204]", verify)
        self.assertIn("archiveweaver_evidence.status == 'pass'", verify)
        self.assertIn("regex_replace('[^A-Za-z0-9_.-]', '_')", verify)
        self.assertIn("regex_escape", verify)
        evidence = (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Validate the controller evidence-root boundary", evidence)
        self.assertIn("check_mode: false", evidence)
        self.assertIn("Require immutable production evidence publication controls", evidence)
        self.assertIn("Publish the sealed evidence bundle to immutable storage", evidence)
        self.assertIn("Verify immutable evidence retention and access logging", evidence)
        self.assertIn("and not (ansible_check_mode | bool)", evidence)
        restore = (ANSIBLE_ROOT / "roles/archiveweaver_restore/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Refuse to execute restore hooks in check mode", restore)
        self.assertIn("restore-drill-", restore)
        self.assertIn("execution_environment", restore)
        self.assertIn("execution_environment_digest", restore)
        self.assertIn("recorded_at", restore)
        self.assertIn("Reject colliding restore evidence filenames", restore)
        failure_drill = (ANSIBLE_ROOT / "roles/archiveweaver_failure/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Refuse to execute failure hooks in check mode", failure_drill)
        self.assertIn("failure-drill-", failure_drill)
        self.assertIn("Reject colliding failure-drill evidence filenames", failure_drill)
        rollback = (ANSIBLE_ROOT / "roles/archiveweaver_rollback/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Refuse to execute rollback hooks in check mode", rollback)
        self.assertIn("rollback-", rollback)
        self.assertIn("Reject colliding rollback evidence filenames", rollback)
        self.assertIn("Run the reviewed post-rollback verification hook", rollback)
        self.assertIn("verification_returncode", rollback)
        self.assertIn("execution_environment_digest", rollback)
        self.assertIn("Load the reviewed rollback identity from the readiness manifest", rollback)
        self.assertIn("Bind rollback to the reviewed release manifest", rollback)
        self.assertIn("rollback_readiness_manifest", rollback)
        rollback_playbook = (ANSIBLE_ROOT / "rollback.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_preflight", rollback_playbook)
        self.assertIn("archiveweaver_rollback_verify_command: []", rollback_playbook)
        self.assertIn("archiveweaver_rollback_release_manifest_verified", rollback_playbook)
        self.assertIn("archiveweaver_certification_change_id: CERT-PLAN", (ANSIBLE_ROOT / "product-certification.yml").read_text(encoding="utf-8"))
        provider_main = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("when: not archiveweaver_is_staging_preview", provider_main)
        workflow = (ANSIBLE_ROOT / "controller/workflow.yml").read_text(encoding="utf-8")
        self.assertIn("required_runtime_bindings", workflow)
        self.assertIn("required_extra_vars", workflow)
        self.assertIn("bash ../../scripts/validate-ansible.sh", workflow)
        self.assertIn("product-certification.yml --check --diff", workflow)
        self.assertIn("failure-drill.yml --check --diff", workflow)
        self.assertIn("archiveweaver_certification_tests", workflow)
        self.assertIn("archiveweaver_certification_change_id", workflow)
        self.assertIn("archiveweaver_failure_tests", workflow)
        self.assertIn("archiveweaver_failure_change_id", workflow)
        self.assertIn("archiveweaver_restore_change_id", workflow)
        self.assertIn("archiveweaver_restore_command", workflow)
        self.assertIn("archiveweaver_fixity_command", workflow)
        self.assertIn("archiveweaver_rollback_verify_command", workflow)
        self.assertIn("archiveweaver_evidence_publish_command", workflow)
        self.assertIn("archiveweaver_evidence_verify_command", workflow)
        self.assertIn("archiveweaver_execution_environment_digest", workflow)
        self.assertIn("archiveweaver_topology_design_approved", workflow)
        self.assertIn("archiveweaver_single_node_production_approved", workflow)
        self.assertIn("image: REPLACE_WITH_APPROVED_EXECUTION_ENVIRONMENT_IMAGE@sha256:REPLACE_WITH_64_HEX_DIGEST", workflow)
        self.assertIn("digest: sha256:REPLACE_WITH_64_HEX_DIGEST", workflow)
        self.assertIn("controller_identity_env: ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST", workflow)
        self.assertIn("archiveweaver_evidence_retention_days", workflow)
        self.assertGreaterEqual(workflow.count("archiveweaver_evidence_publish_enabled"), 5)
        restore_failure_bindings = workflow.split("  restore_and_failure_drills:", 1)[1]
        self.assertIn("archiveweaver_execution_environment_digest", restore_failure_bindings)
        self.assertIn("archiveweaver_release", workflow)
        self.assertIn("archiveweaver_approval_ticket", workflow)
        self.assertIn("archiveweaver_backup_verified", workflow)
        self.assertIn("archiveweaver_release_manifest_verified", workflow)
        self.assertIn("archiveweaver_product_stack_ready", workflow)
        self.assertIn("expand_argument_vars: false", (ANSIBLE_ROOT / "roles/archiveweaver_certification/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("expand_argument_vars: false", (ANSIBLE_ROOT / "roles/archiveweaver_restore/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("expand_argument_vars: false", (ANSIBLE_ROOT / "roles/archiveweaver_failure/tasks/main.yml").read_text(encoding="utf-8"))
        rollback = (ANSIBLE_ROOT / "roles/archiveweaver_rollback/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("expand_argument_vars: false", rollback)
        self.assertIn("approval_ticket", rollback)
        self.assertIn("archiveweaver_restore_change_id: DR-PLAN", (ANSIBLE_ROOT / "restore-drill.yml").read_text(encoding="utf-8"))
        self.assertIn("archiveweaver_failure_change_id: FD-PLAN", (ANSIBLE_ROOT / "failure-drill.yml").read_text(encoding="utf-8"))
        self.assertIn("bash scripts/validate-ansible.sh", (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    def test_playbooks_do_not_contain_intentionally_destructive_operations(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in ANSIBLE_ROOT.rglob("*.yml"))
        for forbidden in ("down -v", "volume prune", "delete pvc", "stonith-enabled=false", "--insecure", "--remove-orphans"):
            self.assertNotIn(forbidden, content.lower())
        self.assertNotIn("ansible.builtin.shell", content)

    def test_provider_digest_stat_checks_use_sha256(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in ANSIBLE_ROOT.rglob("*.yml"))
        self.assertNotRegex(content, r"get_checksum: true(?!\s+checksum_algorithm: sha256)")
