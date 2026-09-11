from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_ROOT = ROOT / "deploy" / "ansible"


class AnsibleEditionTests(unittest.TestCase):
    def test_required_ansible_project_files_exist(self) -> None:
        for relative in (
            "ansible.cfg",
            ".ansible-lint",
            "requirements.in",
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
            "controller/allowed-extra-vars.txt",
            "controller/README.md",
            "../../scripts/validate-controller-contract.py",
            "../../scripts/compile-ansible-lock.py",
            "../../scripts/generate-ansible-sbom.py",
            "execution-environment/Containerfile",
            "execution-environment/requirements.txt",
            "execution-environment/README.md",
            "../../scripts/build-ansible-execution-environment.sh",
            "../../scripts/validate-ansible.sh",
            "../../scripts/run-ansible-operational.sh",
            "../../tests/test-operational-runner.sh",
            "../../scripts/verify-source-identity.sh",
            "../../scripts/verify-readiness-manifest.py",
            "../../scripts/verify-path-boundary.py",
            "inventory/production/hosts.yml.example",
            "inventory/staging/hosts.yml.example",
            "inventory/restore/hosts.yml.example",
            "group_vars/all/main.yml",
            "group_vars/all/vault.yml.example",
            "roles/archiveweaver_preflight/tasks/main.yml",
            "roles/archiveweaver_controller_preflight/tasks/main.yml",
            "roles/archiveweaver_controller_preflight/tasks/hook-boundary.yml",
            "roles/archiveweaver_controller_preflight/tasks/require-complete.yml",
            "roles/archiveweaver_controller_preflight/tasks/require-managed-complete.yml",
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
        self.assertIn(
            "BASE_IMAGE must be a fully qualified lowercase OCI repository with a 64-character SHA-256 digest",
            containerfile,
        )
        self.assertIn("--only-binary=:all:", containerfile)
        self.assertIn("--require-hashes", containerfile)
        self.assertIn("CPython 3.13/3.14 on Linux x86_64", containerfile)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", containerfile)
        self.assertIn('ansible-execution-environment="true"', containerfile)
        self.assertIn("WORKDIR /runner", containerfile)
        self.assertIn("USER 65532:65532", containerfile)
        self.assertIn('ENTRYPOINT ["dumb-init", "--"]', containerfile)
        self.assertIn('CMD ["bash"]', containerfile)

        self.assertEqual(
            (ANSIBLE_ROOT / "requirements.txt").read_bytes(),
            (ANSIBLE_ROOT / "execution-environment/requirements.txt").read_bytes(),
        )
        builder = (ROOT / "scripts/build-ansible-execution-environment.sh").read_text(encoding="utf-8")
        self.assertIn("--base-image", builder)
        self.assertIn("--engine podman|docker", builder)
        self.assertIn("--build-arg", builder)
        self.assertIn("--tag", builder)
        self.assertIn("--source-revision", builder)
        self.assertIn("--user 65532:65532", builder)
        self.assertIn("ansible-playbook --version", builder)
        self.assertIn("ansible-runner --version", builder)
        self.assertIn("dumb-init --version", builder)
        self.assertIn("pwd.getpwuid", builder)
        self.assertIn("ansible-execution-environment", builder)
        self.assertIn("--module-name ping", builder)
        self.assertIn("org.opencontainers.image.revision", builder)
        self.assertIn("{{ index .Labels", builder)
        self.assertIn("{{.Config.User}}", builder)
        self.assertIn('default_user" == "65532:65532', builder)
        self.assertIn("latest", builder)
        validator = (ROOT / "scripts/validate-ansible.sh").read_text(encoding="utf-8")
        self.assertIn("cmp -s requirements.txt execution-environment/requirements.txt", validator)
        self.assertIn('compile-ansible-lock.py" --check', validator)

    def test_ansible_version_bindings_match_the_controller_lock(self) -> None:
        lock = (ANSIBLE_ROOT / "requirements.txt").read_text(encoding="utf-8")
        requirements = dict(
            re.findall(r"(?m)^([a-z0-9-]+)==([^\s\\]+)\s+\\$", lock)
        )
        self.assertGreaterEqual(len(requirements), 20)
        self.assertGreaterEqual(lock.count("--hash=sha256:"), len(requirements))
        self.assertIn(
            "Approved artifact scope: CPython 3.13 and 3.14 on Linux x86_64",
            lock,
        )
        self.assertNotIn(ROOT.as_posix(), lock)
        self.assertNotRegex(lock, r"(?m)^[a-z0-9-]+(?:>=|<=|~=|!=|>|<)")
        for requirement in (ANSIBLE_ROOT / "requirements.in").read_text(
            encoding="utf-8"
        ).splitlines():
            if not requirement or requirement.startswith("#"):
                continue
            name, version = requirement.lower().split("==", 1)
            self.assertEqual(requirements[name], version)
        main_vars = (ANSIBLE_ROOT / "group_vars/all/main.yml").read_text(encoding="utf-8")
        workflow = (ANSIBLE_ROOT / "controller/workflow.yml").read_text(encoding="utf-8")
        self.assertIn(
            f'archiveweaver_ansible_core_version: "{requirements["ansible-core"]}"',
            main_vars,
        )
        self.assertIn(
            f'archiveweaver_ansible_lint_version: "{requirements["ansible-lint"]}"',
            main_vars,
        )
        self.assertIn(
            f'archiveweaver_ansible_runner_version: "{requirements["ansible-runner"]}"',
            main_vars,
        )
        self.assertIn(f'ansible_core: {requirements["ansible-core"]}', workflow)
        self.assertIn(f'ansible_lint: {requirements["ansible-lint"]}', workflow)
        self.assertIn(f'ansible_runner: {requirements["ansible-runner"]}', workflow)

    def test_manifest_template_evidence_records_carry_release_identity(self) -> None:
        manifest = json.loads(
            (ANSIBLE_ROOT / "release-manifest.example.json").read_text(encoding="utf-8")
        )
        service = manifest["service"]
        required = {
            "name",
            "solution",
            "runtime",
            "underlying_runtime",
            "os_id",
            "release",
            "environment",
            "execution_environment_digest",
            "recorded_at",
            "operator",
            "fixture_set",
        }
        evidence_records: list[dict[str, object]] = []

        def collect(value: object) -> None:
            if isinstance(value, dict):
                if "status" in value and isinstance(value.get("evidence"), str):
                    evidence_records.append(value)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(manifest)
        self.assertGreater(len(evidence_records), 20)
        for record in evidence_records:
            self.assertFalse(required - record.keys(), record.get("evidence"))
            self.assertEqual(record["solution"], service["solution_id"])
            self.assertEqual(record["runtime"], service["runtime"])
            self.assertEqual(record["underlying_runtime"], service["underlying_runtime"])
            self.assertEqual(record["os_id"], service["os_id"])
        certification = manifest["product_certification"]["test_matrix"]
        failure_tests = manifest["resilience"]["failure_tests"]
        self.assertEqual(
            {record["name"] for record in certification},
            {"dependencies", "smoke", "migration", "formats", "api"},
        )
        self.assertEqual(
            {record["name"] for record in failure_tests},
            {"node", "service", "dependency", "storage"},
        )
        paths = [record["evidence"] for record in evidence_records]
        self.assertEqual(len(paths), len(set(paths)))

    def test_core_operational_playbooks_pin_serial_execution(self) -> None:
        for playbook in ("site.yml", "verify.yml", "repair.yml", "restore-drill.yml", "failure-drill.yml", "rollback.yml", "product-certification.yml"):
            content = (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8")
            self.assertIn("serial: 1", content, playbook)

    def test_apply_and_repair_defaults_are_fail_closed(self) -> None:
        main_vars = (ANSIBLE_ROOT / "group_vars/all/main.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_apply: false", main_vars)
        self.assertIn("archiveweaver_repair_apply: false", main_vars)
        self.assertIn("archiveweaver_staging_preview: false", main_vars)
        self.assertIn("archiveweaver_backup_verified: false", main_vars)
        self.assertIn("archiveweaver_product_stack_ready: false", main_vars)
        self.assertIn('archiveweaver_bundle_root:', main_vars)
        self.assertIn('archiveweaver_readiness_python: "{{ ansible_playbook_python }}"', main_vars)
        self.assertIn('archiveweaver_readiness_manifest_path: "{{ archiveweaver_bundle_root }}/release-manifest.json"', main_vars)
        self.assertIn("archiveweaver_runtime: rke2", main_vars)
        self.assertIn("archiveweaver_environment: production", main_vars)
        self.assertIn("archiveweaver_observe_enabled: false", main_vars)
        self.assertIn("archiveweaver_manage_packages: false", main_vars)
        self.assertIn("archiveweaver_external_consensus_ready: false", main_vars)
        self.assertIn("archiveweaver_external_storage_ready: false", main_vars)
        self.assertIn('archiveweaver_ansible_core_version: "2.21.4"', main_vars)
        self.assertIn('archiveweaver_ansible_lint_version: "26.8.0"', main_vars)
        self.assertIn('archiveweaver_ansible_runner_version: "2.4.3"', main_vars)
        self.assertIn('archiveweaver_execution_environment_digest: ""', main_vars)
        self.assertIn('archiveweaver_readiness_pythonpath: "{{ archiveweaver_bundle_root }}/../../src"', main_vars)
        self.assertIn('archiveweaver_product_stack_sha256: ""', main_vars)
        self.assertIn('archiveweaver_kustomize_bundle_sha256: ""', main_vars)
        self.assertIn('archiveweaver_provider_bundle_sha256: ""', main_vars)
        self.assertIn('"change_ticket": "CHG-REPLACE"', (ANSIBLE_ROOT / "release-manifest.example.json").read_text(encoding="utf-8"))
        self.assertIn("Verify the repository readiness score on the controller", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Require a regular controller readiness manifest", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('runtime') == 'ansible'", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('underlying_runtime') == archiveweaver_runtime", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(".get('environment') == archiveweaver_environment", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Verify the pinned Ansible Core on the controller", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn(
            "Require shared or replicated storage for multi-node Swarm",
            (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"),
        )
        self.assertIn("Seal the controller evidence root with a SHA-256 index", (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Verify the sealed controller evidence index", (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8"))
        for playbook, apply_var in (
            ("product-certification.yml", "archiveweaver_certification_apply"),
            ("failure-drill.yml", "archiveweaver_failure_apply"),
            ("restore-drill.yml", "archiveweaver_restore_apply"),
            ("rollback.yml", "archiveweaver_rollback_apply"),
        ):
            playbook_text = (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8")
            self.assertIn(apply_var + " | default(false) | bool", playbook_text)
        self.assertIn("archiveweaver_operator: \"\"", main_vars)
        self.assertIn("archiveweaver_fixture_set: \"\"", main_vars)
        self.assertIn("archiveweaver_evidence_environment: production", main_vars)
        self.assertIn("archiveweaver_evidence_publish_enabled: false", main_vars)
        self.assertIn("archiveweaver_evidence_publish_command: []", main_vars)
        self.assertIn("archiveweaver_evidence_verify_command: []", main_vars)
        self.assertIn('archiveweaver_evidence_publish_command_sha256: ""', main_vars)
        self.assertIn('archiveweaver_evidence_publish_command_argv_sha256: ""', main_vars)
        self.assertIn('archiveweaver_evidence_verify_command_sha256: ""', main_vars)
        self.assertIn('archiveweaver_evidence_verify_command_argv_sha256: ""', main_vars)
        self.assertIn('archiveweaver_restore_command_sha256: ""', main_vars)
        self.assertIn('archiveweaver_restore_command_argv_sha256: ""', main_vars)
        self.assertIn('archiveweaver_fixity_command_sha256: ""', main_vars)
        self.assertIn('archiveweaver_fixity_command_argv_sha256: ""', main_vars)
        self.assertIn('archiveweaver_check_command_sha256: ""', main_vars)
        self.assertIn('archiveweaver_check_command_argv_sha256: ""', main_vars)
        self.assertIn("archiveweaver_evidence_retention_days: 0", main_vars)
        host = (ANSIBLE_ROOT / "roles/archiveweaver_host/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Create application, log, and release-record directories", host)
        provider_main = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Record the verified release identity after provider reconciliation", provider_main)
        self.assertIn("execution_environment_digest", provider_main)
        self.assertIn("provider_bundle_sha256", provider_main)
        self.assertIn("product_stack_sha256", provider_main)
        self.assertIn("kustomize_bundle_sha256", provider_main)
        self.assertIn("source_commit", provider_main)
        self.assertIn("readiness_manifest_sha256", provider_main)
        self.assertIn("when: archiveweaver_apply | bool", provider_main)
        self.assertLess(
            provider_main.index("Fail closed for Pacemaker deployment resources"),
            provider_main.index("Record the verified release identity after provider reconciliation"),
        )

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
        self.assertIn("archiveweaver_readiness_manifest_path", restore_inventory)

    def test_controller_preflight_rejects_empty_operational_target_groups(self) -> None:
        controller_preflight = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require a non-empty controller target group", controller_preflight)
        self.assertIn("archiveweaver_controller_target_group", controller_preflight)
        self.assertIn("intersect(query('ansible.builtin.inventory_hostnames'", controller_preflight)
        self.assertIn("ansible_limit | default('all', true)", controller_preflight)
        self.assertIn("Reject partial inventory limits for operational workflows", controller_preflight)
        self.assertIn("archiveweaver_controller_preflight_entrypoint", controller_preflight)
        for playbook, target_group in (
            ("site.yml", "archiveweaver_nodes"),
            ("verify.yml", "archiveweaver_nodes"),
            ("repair.yml", "archiveweaver_nodes"),
            ("rollback.yml", "archiveweaver_nodes"),
            ("product-certification.yml", "archiveweaver_certification"),
            ("failure-drill.yml", "archiveweaver_failure"),
            ("restore-drill.yml", "archiveweaver_restore"),
        ):
            playbook_text = (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8")
            self.assertIn(f"archiveweaver_controller_target_group: {target_group}", playbook_text)

    def test_preflight_enforces_consensus_and_fencing_invariants(self) -> None:
        preflight = (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require an odd control-plane shape for consensus runtimes", preflight)
        self.assertIn("Require an external quorum design for two-node consensus", preflight)
        self.assertIn(
            "Require shared or replicated storage for multi-node Swarm",
            preflight,
        )
        self.assertIn("archiveweaver_external_storage_ready | bool", preflight)
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
        self.assertIn("Reject documentation-only production inventory endpoints", preflight)
        self.assertIn("Inspect managed filesystem anchors before any host mutation", preflight)
        self.assertIn("Reject symlinked managed filesystem anchors", preflight)
        self.assertIn("- /srv/archiveweaver", preflight)
        self.assertIn("- /var/log/archiveweaver", preflight)
        self.assertIn("- /etc/containers/systemd", preflight)
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
        self.assertIn("Reject tag-filtered production mutations and repairs", preflight)
        self.assertIn("'all' in (ansible_run_tags | default(['all']))", preflight)
        self.assertIn("not archiveweaver_preflight_is_staging_preview | bool", preflight)
        self.assertIn("Bind the reviewed Compose or Swarm digest to readiness", preflight)
        self.assertIn("Bind the reviewed Kustomize digest to readiness", preflight)
        self.assertIn("provider_bundle.remote_digest", preflight)
        self.assertIn("Bind the reviewed raw or Quadlet digest to readiness", preflight)
        control_collection = preflight.split("- name: Collect control-plane failure-domain labels", 1)[1].split(
            "- name: Require distinct control-plane failure domains", 1
        )[0]
        self.assertIn("archiveweaver_run_verification | bool", control_collection)
        self.assertIn("Require a health endpoint for non-systemd operations", preflight)
        self.assertIn("archiveweaver_health_url is not search('[@?#$%&;]')", preflight)
        self.assertIn("archiveweaver_health_url is not search('\\\\')", preflight)
        health_task = preflight.split("- name: Require a health endpoint for non-systemd operations", 1)[1].split("- name:", 1)[0]
        self.assertIn("archiveweaver_apply | bool or archiveweaver_repair_apply | bool or archiveweaver_run_verification | bool", health_task)
        self.assertIn("Bind standard-playbook evidence to its target environment", preflight)
        self.assertIn("archiveweaver_preflight_provider_probe_hosts", preflight)
        observe = (ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("^[1-9][0-9]*(s|min|h|d)$", observe)
        self.assertIn("archiveweaver_health_url is not search('[@?#$%&;]')", observe)
        self.assertIn("archiveweaver_health_url is not search('\\\\')", observe)
        self.assertIn("Reject colliding managed-host evidence filenames", preflight)
        self.assertIn("archiveweaver_ansible_core_version is match", preflight)
        self.assertIn("(ansible_skip_tags | default([]) | length) == 0", preflight)
        self.assertIn("Bind the live execution environment to the reviewed readiness manifest", preflight)
        self.assertIn("ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST", preflight)
        controller_preflight = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require the pinned Ansible Core execution environment", controller_preflight)
        self.assertIn("Require the pinned Ansible Runner execution environment", controller_preflight)
        self.assertIn("Inspect the controller Ansible Lint version", controller_preflight)
        self.assertIn("Require the pinned Ansible Lint execution environment", controller_preflight)
        self.assertIn("Reject tag-filtered operational workflows", controller_preflight)
        self.assertIn("(ansible_skip_tags | default([]) | length) == 0", controller_preflight)
        self.assertIn("Attest completed controller preflight", controller_preflight)
        self.assertIn("Begin controller preflight transaction", controller_preflight)
        self.assertGreater(
            controller_preflight.rfind("- name: Attest completed controller preflight"),
            controller_preflight.rfind("- name: Require applied workflows to match the signed readiness identity"),
        )
        self.assertIn("Reject symlinked controller path components", controller_preflight)
        self.assertIn("archiveweaver_readiness_python == ansible_playbook_python", controller_preflight)
        self.assertIn("Check controller path components before any local write", controller_preflight)
        self.assertIn("verify-path-boundary.py", controller_preflight)
        self.assertIn("Require controller paths to stay within real directories", controller_preflight)
        provider_probe = preflight.split("- name: Check the provider command without changing the managed host", 1)[1].split("- name:", 1)[0]
        self.assertIn("no_log: true", provider_probe)
        python_probe = preflight.split("- name: Check the managed Python interpreter", 1)[1].split("- name:", 1)[0]
        self.assertIn("no_log: true", python_probe)
        observe = (ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8")
        checker_probe = observe.split("- name: Verify the checker executable is present", 1)[1].split("- name:", 1)[0]
        self.assertIn("no_log: true", checker_probe)
        controller_path_boundary = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/path-boundary.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_controller_path_boundary_paths", controller_path_boundary)
        completion_guard = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/require-complete.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_controller_preflight_completed", completion_guard)
        self.assertIn("ansible_skip_tags", completion_guard)
        self.assertIn("['always', 'controller']", completion_guard)
        managed_completion_guard = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/require-managed-complete.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_preflight_completed", managed_completion_guard)
        self.assertIn("ansible_skip_tags", managed_completion_guard)
        self.assertIn("Attest completed managed-host preflight", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        self.assertIn("Begin managed-host preflight transaction", (ANSIBLE_ROOT / "roles/archiveweaver_preflight/tasks/main.yml").read_text(encoding="utf-8"))
        hook_boundary = (ANSIBLE_ROOT / "roles/archiveweaver_controller_preflight/tasks/hook-boundary.yml").read_text(encoding="utf-8")
        self.assertIn("item.command[0] is match('^/')", hook_boundary)
        self.assertIn("checksum_algorithm: sha256", hook_boundary)
        self.assertIn("argv: [realpath, -e, --", hook_boundary)
        self.assertIn("item.stat.mode[0] == '0'", hook_boundary)
        self.assertIn("item.stat.mode[-1] not in", hook_boundary)
        self.assertIn("item.stat.checksum | default('') == item.item.sha256", hook_boundary)
        self.assertIn("item.argv_sha256 is match('^[0-9a-f]{64}$')", hook_boundary)
        self.assertIn("to_json(ensure_ascii=true, separators=[',', ':'])", hook_boundary)
        self.assertIn("== item.argv_sha256", hook_boundary)
        for hook_role in (
            "archiveweaver_certification",
            "archiveweaver_failure",
            "archiveweaver_restore",
            "archiveweaver_rollback",
            "archiveweaver_evidence",
        ):
            hook_role_text = (ANSIBLE_ROOT / f"roles/{hook_role}/tasks/main.yml").read_text(encoding="utf-8")
            self.assertIn("hook-boundary.yml", hook_role_text)
        for guarded_role in (
            "archiveweaver_preflight",
            "archiveweaver_host",
            "archiveweaver_provider",
            "archiveweaver_observe",
            "archiveweaver_verify",
            "archiveweaver_repair",
            "archiveweaver_restore",
            "archiveweaver_failure",
            "archiveweaver_certification",
            "archiveweaver_rollback",
            "archiveweaver_evidence",
        ):
            guarded_text = (ANSIBLE_ROOT / f"roles/{guarded_role}/tasks/main.yml").read_text(encoding="utf-8")
            self.assertIn("require-complete.yml", guarded_text)
        for managed_guarded_role in ("archiveweaver_host", "archiveweaver_provider", "archiveweaver_observe", "archiveweaver_verify", "archiveweaver_repair"):
            managed_guarded_text = (ANSIBLE_ROOT / f"roles/{managed_guarded_role}/tasks/main.yml").read_text(encoding="utf-8")
            self.assertIn("require-managed-complete.yml", managed_guarded_text)
        self.assertIn("verify-path-boundary.py", controller_path_boundary)
        self.assertIn("Require local evidence paths to stay within real directories", controller_path_boundary)
        for role in ("archiveweaver_certification", "archiveweaver_failure", "archiveweaver_repair", "archiveweaver_restore", "archiveweaver_rollback", "archiveweaver_verify"):
            evidence_role = (ANSIBLE_ROOT / f"roles/{role}/tasks/main.yml").read_text(encoding="utf-8")
            self.assertIn("archiveweaver_controller_preflight/tasks/path-boundary.yml", evidence_role)
            self.assertIn("archiveweaver_controller_path_boundary_paths", evidence_role)
        self.assertIn("Determine whether immutable source verification applies", controller_preflight)
        self.assertIn("ARCHIVEWEAVER_IMMUTABLE_REF", controller_preflight)
        self.assertIn("ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS", controller_preflight)
        self.assertIn("ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", controller_preflight)
        self.assertIn("Require a controller-protected readiness manifest digest", controller_preflight)
        self.assertIn("checksum_algorithm: sha256", controller_preflight)
        self.assertIn("Require the approved readiness manifest bytes", controller_preflight)
        self.assertIn("Verify the controller-approved operational readiness manifest", controller_preflight)
        self.assertIn("Require the operational readiness manifest verifier to pass", controller_preflight)
        self.assertIn("Load the controller-approved readiness identity", controller_preflight)
        self.assertIn("Bind every applied workflow to the approved readiness identity", controller_preflight)
        self.assertIn(
            "get('service', {}).get('environment') == archiveweaver_evidence_environment",
            " ".join(controller_preflight.split()),
        )
        self.assertIn("verify-source-identity.sh", controller_preflight)
        self.assertIn("Require signed and clean controller source", controller_preflight)
        self.assertIn("Require an immutable execution-environment digest for applied workflows", controller_preflight)
        self.assertIn("ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST", controller_preflight)
        self.assertIn("Determine whether the final readiness gate applies", controller_preflight)
        self.assertIn("archiveweaver_controller_preflight_readiness_gate_active", controller_preflight)
        self.assertIn("Validate the controller readiness manifest boundary", controller_preflight)
        self.assertIn("Require a regular controller readiness manifest", controller_preflight)
        self.assertIn("ansible_config_file | default(playbook_dir ~ '/ansible.cfg', true)", controller_preflight)
        for playbook in ("product-certification.yml", "restore-drill.yml", "failure-drill.yml", "rollback.yml"):
            self.assertIn("archiveweaver_controller_preflight", (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8"))
        for playbook in ("site.yml", "verify.yml", "repair.yml"):
            self.assertIn("archiveweaver_controller_preflight", (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8"))
        self.assertGreaterEqual((ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8").count("diff: false"), 3)
        failure = (ANSIBLE_ROOT / "roles/archiveweaver_failure/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("'node' in (archiveweaver_failure_tests | map(attribute='name') | list)", failure)
        self.assertIn("Reject duplicate failure-drill hook names", failure)
        self.assertIn("| unique | length", failure)
        self.assertIn("execution_environment_digest", failure)
        docker = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker.yml").read_text(encoding="utf-8")
        self.assertIn("Require a staged product Compose stack", docker)
        self.assertIn("Require the reviewed Compose stack digest", docker)
        self.assertIn("Require immutable images in the rendered Compose model", docker)
        self.assertNotIn("Render the reviewed Compose envelope", docker)
        swarm = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker-swarm.yml").read_text(encoding="utf-8")
        self.assertIn("Require the reviewed Swarm stack digest", swarm)
        self.assertIn("Require immutable images in the rendered Swarm model", swarm)
        raw = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/raw.yml").read_text(encoding="utf-8")
        self.assertIn("not ansible_check_mode | bool", raw)
        self.assertIn("archiveweaver_exec_start is not search('%')", raw)
        self.assertIn("Render the raw provider unit into staging", raw)
        self.assertIn("Require the staged raw provider unit digest before installation", raw)
        self.assertIn("Install the verified hardened systemd unit", raw)
        self.assertIn("remote_src: true", raw)
        self.assertLess(
            raw.index("Require the staged raw provider unit digest before installation"),
            raw.index("Install the verified hardened systemd unit"),
        )
        quadlet = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/podman-quadlet.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_image is match('^[A-Za-z0-9]", quadlet)
        self.assertIn("immutable image digest", quadlet)
        self.assertIn("Render the Quadlet provider files into staging", quadlet)
        self.assertIn("Require the staged Quadlet provider digest before installation", quadlet)
        self.assertIn("Install the verified Quadlet provider files", quadlet)
        self.assertIn("remote_src: true", quadlet)
        self.assertIn("not ansible_check_mode | bool", quadlet)
        self.assertLess(
            quadlet.index("Require the staged Quadlet provider digest before installation"),
            quadlet.index("Install the verified Quadlet provider files"),
        )
        self.assertIn("notify: Restart ArchiveWeaver service", quadlet)
        self.assertIn("archiveweaver-{{ archiveweaver_solution_id }}.network", quadlet)
        self.assertIn("archiveweaver-{{ archiveweaver_solution_id }}.volume", quadlet)
        self.assertGreaterEqual(quadlet.count("diff: false"), 3)
        immutable_images = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/require-immutable-images.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_provider_rendered_image_references", immutable_images)
        self.assertIn("@sha256:[0-9a-f]{64}", immutable_images)
        self.assertIn("latest", immutable_images)
        volume_template = (ANSIBLE_ROOT / "roles/archiveweaver_provider/templates/archiveweaver.volume.j2").read_text(encoding="utf-8")
        self.assertIn("Device={{ archiveweaver_data_root }}", volume_template)
        self.assertIn("Options=bind", volume_template)
        kubernetes = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        self.assertIn("Require a staged product Kustomize bundle", kubernetes)
        kubernetes_probe = kubernetes.split("- name: Validate the Kubernetes cluster before apply", 1)[1].split("- name:", 1)[0]
        self.assertIn("no_log: true", kubernetes_probe)
        self.assertIn("Require the reviewed Kustomize bundle digest", kubernetes)
        self.assertIn("Require immutable images in the rendered Kustomize model", kubernetes)
        self.assertIn("replace(archiveweaver_kustomize_path", kubernetes)
        self.assertIn("Reject symlinks inside the staged product Kustomize bundle", kubernetes)
        self.assertIn("Reject ambiguous or nonportable Kustomize filenames", kubernetes)
        self.assertIn("^[A-Za-z0-9._/-]+$", kubernetes)
        self.assertIn("Render the staged product Kustomize bundle read-only", kubernetes)
        verify_bundle = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/verify-bundle.yml").read_text(encoding="utf-8")
        self.assertIn("Require the verified Compose bundle to match its release digest", verify_bundle)
        self.assertIn("Require the verified Kustomize bundle to match its release digest", verify_bundle)
        self.assertIn("Require immutable images in the verified Compose model", verify_bundle)
        self.assertIn("Require immutable images in the verified Swarm model", verify_bundle)
        self.assertIn("Require immutable images in the verified Kustomize model", verify_bundle)
        self.assertIn("replace(archiveweaver_kustomize_path", verify_bundle)
        self.assertIn("Reject symlinks inside the verified Kustomize bundle", verify_bundle)
        self.assertIn(
            "Reject ambiguous or nonportable verified Kustomize filenames",
            verify_bundle,
        )
        self.assertIn("^[A-Za-z0-9._/-]+$", verify_bundle)
        self.assertIn("Require the verified raw provider unit to match its release digest", verify_bundle)
        self.assertIn("Require the verified Quadlet provider to match its release digest", verify_bundle)
        self.assertIn("Define solution-scoped Quadlet files during verification", verify_bundle)
        self.assertIn("archiveweaver-{{ archiveweaver_solution_id }}.network", verify_bundle)
        self.assertIn("archiveweaver-{{ archiveweaver_solution_id }}.volume", verify_bundle)
        repair = (ANSIBLE_ROOT / "roles/archiveweaver_repair/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Build redacted repair evidence", repair)
        self.assertIn("execution_environment", repair)
        self.assertIn("no_log: true", repair)
        self.assertIn("Require the reviewed Compose repair bundle", repair)
        self.assertIn("Require the reviewed Swarm repair bundle", repair)
        self.assertIn("Verify the staged provider bundle before any repair mutation", repair)
        self.assertIn("archiveweaver_provider/tasks/verify-bundle.yml", repair)
        self.assertLess(
            repair.index("Verify the staged provider bundle before any repair mutation"),
            repair.index("Restart the named systemd service"),
        )
        self.assertIn("Reconcile the declared Compose workload", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker.yml").read_text(encoding="utf-8"))
        self.assertIn("Deploy the reviewed Swarm stack", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/docker-swarm.yml").read_text(encoding="utf-8"))
        self.assertIn("Apply the reviewed product Kustomize bundle", (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8"))
        self.assertIn("inventory_hostname == groups['archiveweaver_app'][0]", repair)
        self.assertIn("inventory_hostname == groups['archiveweaver_control'][0]", repair)
        certification = (ANSIBLE_ROOT / "roles/archiveweaver_certification/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require the complete reviewed product test matrix", certification)
        self.assertIn("Require safe product certification argv elements", certification)
        self.assertIn("Require real certification identity for an applied matrix", certification)
        self.assertIn("Refuse to execute certification hooks in check mode", certification)
        self.assertIn("Run the reviewed product certification hooks", certification)
        self.assertIn("'underlying_runtime': archiveweaver_runtime", certification)
        self.assertIn("'execution_environment_digest': archiveweaver_execution_environment_digest", certification)
        self.assertIn("inventory_hostname == groups['archiveweaver_certification'][0]", certification)
        verify = (ANSIBLE_ROOT / "roles/archiveweaver_verify/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("host-verification-", verify)
        self.assertIn("Bind the managed release record to the approved identity", verify)
        self.assertIn("archiveweaver_verify_release_record.source_commit", verify)
        self.assertIn("release_record_sha256", verify)
        self.assertIn("archiveweaver_runtime in ['raw', 'podman-quadlet', 'docker'", verify)
        self.assertIn("archiveweaver_operator", verify)
        self.assertIn("execution_environment", verify)
        self.assertIn("execution_environment_digest", verify)
        self.assertIn("follow_redirects: none", verify)
        self.assertIn("status_code: [200, 201, 202, 204]", verify)
        self.assertIn("archiveweaver_verify_evidence.status == 'pass'", verify)
        self.assertIn("regex_replace('[^A-Za-z0-9_.-]', '_')", verify)
        self.assertIn("regex_escape", verify)
        self.assertIn("Inspect controller evidence boundaries before writing", verify)
        self.assertIn("Reject symlinked controller evidence boundaries", verify)
        evidence = (ANSIBLE_ROOT / "roles/archiveweaver_evidence/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Require the upstream managed operation to complete before sealing", evidence)
        self.assertIn("archiveweaver_evidence_completion_fact", evidence)
        self.assertIn("archiveweaver_evidence_completion_hosts", evidence)
        self.assertIn("Validate the controller evidence-root boundary", evidence)
        self.assertIn("Inspect the controller evidence root before writing", evidence)
        self.assertIn("Reject a symlinked controller evidence root", evidence)
        self.assertIn("check_mode: false", evidence)
        self.assertIn("Require immutable production evidence publication controls", evidence)
        self.assertIn("Publish the sealed evidence bundle to immutable storage", evidence)
        self.assertIn("Verify immutable evidence retention and access logging", evidence)
        self.assertIn("Re-verify the local evidence index after publication", evidence)
        self.assertIn("archiveweaver_evidence_post_publish_verify_result.rc == 0", evidence)
        observe = (ANSIBLE_ROOT / "roles/archiveweaver_observe/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("hook-boundary.yml", observe)
        self.assertIn("health-check", observe)
        self.assertIn("archiveweaver_observe_command_argv", observe)
        self.assertIn("- --solution", observe)
        self.assertIn("- --url", observe)
        self.assertIn("and not (ansible_check_mode | bool)", evidence)
        self.assertIn("or (archiveweaver_evidence_seal_enabled | default(false) | bool)", evidence)
        restore = (ANSIBLE_ROOT / "roles/archiveweaver_restore/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Refuse to execute restore hooks in check mode", restore)
        self.assertIn("Require safe restore and fixity argv elements", restore)
        self.assertIn("restore-drill-", restore)
        self.assertIn("execution_environment", restore)
        self.assertIn("execution_environment_digest", restore)
        self.assertIn("recorded_at", restore)
        self.assertIn("Reject colliding restore evidence filenames", restore)
        self.assertIn("Inspect controller evidence boundaries before writing", restore)
        self.assertIn("Reject symlinked controller evidence boundaries", restore)
        self.assertIn("Write independent restore and fixity evidence", restore)
        self.assertIn("'evidence': (archiveweaver_restore_evidence_dir", restore)
        failure_drill = (ANSIBLE_ROOT / "roles/archiveweaver_failure/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Refuse to execute failure hooks in check mode", failure_drill)
        self.assertIn("Require safe failure-drill argv elements", failure_drill)
        self.assertIn("failure-drill-", failure_drill)
        self.assertIn("Reject colliding failure-drill evidence filenames", failure_drill)
        self.assertIn("Inspect controller evidence boundaries before writing", failure_drill)
        self.assertIn("Reject symlinked controller evidence boundaries", failure_drill)
        self.assertIn("Write independently attributable failure-domain evidence", failure_drill)
        self.assertIn("'evidence': (archiveweaver_failure_evidence_dir", failure_drill)
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
        self.assertIn("Inspect controller evidence boundaries before writing", rollback)
        self.assertIn("Reject symlinked controller evidence boundaries", rollback)
        self.assertIn("Inspect controller evidence boundaries before writing", certification)
        self.assertIn("Reject symlinked controller evidence boundaries", certification)
        rollback_playbook = (ANSIBLE_ROOT / "rollback.yml").read_text(encoding="utf-8")
        self.assertIn("archiveweaver_preflight", rollback_playbook)
        self.assertIn("archiveweaver_rollback_verify_command: []", rollback_playbook)
        self.assertIn("archiveweaver_rollback_release_manifest_verified", rollback_playbook)
        self.assertIn("archiveweaver_certification_change_id: CERT-PLAN", (ANSIBLE_ROOT / "product-certification.yml").read_text(encoding="utf-8"))
        provider_main = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("when: not archiveweaver_preflight_is_staging_preview", provider_main)
        workflow = (ANSIBLE_ROOT / "controller/workflow.yml").read_text(encoding="utf-8")
        self.assertIn("required_runtime_bindings", workflow)
        self.assertIn("depends_on:", workflow)
        self.assertIn("required_extra_vars", workflow)
        self.assertIn("source-integrity", workflow)
        self.assertIn("operational_runner:", workflow)
        self.assertIn("path: scripts/run-ansible-operational.sh", workflow)
        self.assertIn("--start-at-task", workflow)
        self.assertIn("--step", workflow)
        for workflow_id in (
            "staging-preview",
            "product-certification",
            "failure-domain-drill",
            "backup-and-restore-gate",
            "production-apply",
            "production-post-apply-verify",
            "production-verify",
            "production-repair",
            "production-rollback",
        ):
            workflow_section = workflow.split(f"  - id: {workflow_id}\n", 1)[1].split("\n  - id:", 1)[0]
            self.assertIn("bash ../../scripts/run-ansible-operational.sh", workflow_section)
        self.assertIn("ARCHIVEWEAVER_IMMUTABLE_REF", workflow)
        self.assertIn("ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", workflow)
        self.assertIn("scripts/verify-readiness-manifest.py", workflow)
        readiness_section = workflow.split("  - id: readiness\n", 1)[1].split("\n  - id:", 1)[0]
        self.assertIn("commands:", readiness_section)
        self.assertIn("archiveweaver readiness", readiness_section)
        self.assertIn("required_environment:", readiness_section)
        self.assertIn("readiness:", workflow.split("required_runtime_bindings:", 1)[1])
        staging_preview_section = workflow.split("  - id: staging-preview\n", 1)[1].split("\n  - id:", 1)[0]
        for binding in (
            "archiveweaver_solution_id",
            "archiveweaver_release",
            "archiveweaver_os_id",
            "archiveweaver_runtime",
            "archiveweaver_change_id",
            "archiveweaver_kustomize_path",
            "archiveweaver_kustomize_bundle_sha256",
            "archiveweaver_kubeconfig",
            "archiveweaver_health_url",
            "archiveweaver_execution_environment_digest",
        ):
            self.assertIn(binding, staging_preview_section)
        for runtime, bindings in {
            "raw": ("archiveweaver_exec_start", "archiveweaver_provider_bundle_sha256"),
            "podman-quadlet": ("archiveweaver_image", "archiveweaver_provider_bundle_sha256"),
            "docker": ("archiveweaver_compose_path", "archiveweaver_product_stack_sha256"),
            "docker-swarm": ("archiveweaver_compose_path", "archiveweaver_product_stack_sha256"),
            "k3s": ("archiveweaver_kustomize_path", "archiveweaver_kustomize_bundle_sha256", "archiveweaver_kubeconfig"),
            "rke2": ("archiveweaver_kustomize_path", "archiveweaver_kustomize_bundle_sha256", "archiveweaver_kubeconfig"),
            "k0s": ("archiveweaver_kustomize_path", "archiveweaver_kustomize_bundle_sha256", "archiveweaver_kubeconfig"),
            "microk8s": ("archiveweaver_kustomize_path", "archiveweaver_kustomize_bundle_sha256", "archiveweaver_kubeconfig"),
        }.items():
            runtime_match = re.search(
                rf"(?ms)^      {re.escape(runtime)}:\n(?P<body>.*?)(?=^      [A-Za-z0-9_-]+:|\Z)",
                staging_preview_section,
            )
            self.assertIsNotNone(runtime_match)
            runtime_section = runtime_match.group("body")
            for binding in bindings:
                self.assertIn(binding, runtime_section)
        self.assertIn("unsupported_runtimes:\n        - pacemaker", staging_preview_section)
        self.assertIn("product_certification:", workflow)
        self.assertIn("restore_and_failure_drills:", workflow)
        for binding in (
            "archiveweaver_provider_bundle_sha256",
            "archiveweaver_product_stack_sha256",
            "archiveweaver_kustomize_bundle_sha256",
            "archiveweaver_kubeconfig",
            "archiveweaver_health_url",
        ):
            self.assertIn(binding, workflow)
        for workflow_id in ("production-apply", "production-post-apply-verify", "production-verify", "production-repair", "production-rollback"):
            workflow_section = workflow.split(f"  - id: {workflow_id}\n", 1)[1].split("\n  - id:", 1)[0]
            for binding in (
                "archiveweaver_provider_bundle_sha256",
                "archiveweaver_product_stack_sha256",
                "archiveweaver_kustomize_bundle_sha256",
                "archiveweaver_kubeconfig",
                "archiveweaver_health_url",
            ):
                self.assertIn(binding, workflow_section)
        for workflow_id, bindings in {
            "production-apply": ("archiveweaver_change_id",),
            "production-verify": ("archiveweaver_change_id",),
            "production-rollback": (
                "archiveweaver_change_id",
                "archiveweaver_rollback_change_id",
                "archiveweaver_rollback_environment",
                "archiveweaver_rollback_command",
                "archiveweaver_evidence_environment",
            ),
        }.items():
            workflow_section = workflow.split(f"  - id: {workflow_id}\n", 1)[1].split("\n  - id:", 1)[0]
            for binding in bindings:
                self.assertIn(binding, workflow_section)
        for workflow_id, dependency in {
            "catalog-and-tests": "source-integrity",
            "ansible-quality": "catalog-and-tests",
            "staging-preview": "ansible-quality",
            "product-certification": "staging-preview",
            "failure-domain-drill": "product-certification",
            "backup-and-restore-gate": "failure-domain-drill",
            "readiness": "backup-and-restore-gate",
            "production-approval": "readiness",
            "production-apply": "production-approval",
            "production-post-apply-verify": "production-apply",
            "production-verify": "readiness",
            "production-repair": "production-repair-approval",
            "production-rollback": "production-rollback-approval",
        }.items():
            workflow_section = workflow.split(f"  - id: {workflow_id}\n", 1)[1].split("\n  - id:", 1)[0]
            self.assertIn(f"depends_on:\n      - {dependency}", workflow_section)
        self.assertIn("production_lock: archiveweaver-production", workflow)
        self.assertIn("max_concurrent_production_workflows: 1", workflow)
        self.assertGreaterEqual(workflow.count("resource_lock: archiveweaver-production"), 3)
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
        self.assertIn("- id: production-repair", workflow)
        self.assertIn("- id: production-post-apply-verify", workflow)
        self.assertIn("production-post-apply-verify", workflow)
        self.assertIn("archiveweaver_change_id", workflow)
        self.assertGreaterEqual(workflow.count("resource_lock: archiveweaver-production"), 4)
        self.assertLess(workflow.index("- id: production-repair-approval"), workflow.index("- id: production-repair\n"))
        self.assertIn("approval_node: production-approval", workflow)
        self.assertIn("approval_node: production-repair-approval", workflow)
        self.assertIn("approval_node: production-rollback-approval", workflow)
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

    def test_evidence_is_sealed_only_after_all_managed_hosts_complete(self) -> None:
        for playbook in (
            "site.yml",
            "verify.yml",
            "repair.yml",
            "product-certification.yml",
            "restore-drill.yml",
            "failure-drill.yml",
            "rollback.yml",
        ):
            content = (ANSIBLE_ROOT / playbook).read_text(encoding="utf-8")
            evidence_role = "- role: archiveweaver_evidence"
            self.assertEqual(content.count(evidence_role), 1, playbook)
            evidence_position = content.index(evidence_role)
            evidence_play_start = content.rfind("\n- name:", 0, evidence_position)
            evidence_play = content[evidence_play_start:]
            self.assertIn("hosts: localhost", evidence_play, playbook)
            self.assertIn("connection: local", evidence_play, playbook)
            self.assertIn("tags: [evidence]", evidence_play, playbook)
            self.assertNotIn(evidence_role, content[:evidence_position], playbook)
            self.assertIn("archiveweaver_evidence_completion_fact:", evidence_play, playbook)
            self.assertIn("archiveweaver_evidence_completion_hosts:", evidence_play, playbook)

        for role, fact in (
            ("archiveweaver_verify", "archiveweaver_verify_completed"),
            ("archiveweaver_repair", "archiveweaver_repair_completed"),
            ("archiveweaver_certification", "archiveweaver_certification_completed"),
            ("archiveweaver_failure", "archiveweaver_failure_completed"),
            ("archiveweaver_restore", "archiveweaver_restore_completed"),
            ("archiveweaver_rollback", "archiveweaver_rollback_completed"),
        ):
            role_text = (ANSIBLE_ROOT / f"roles/{role}/tasks/main.yml").read_text(encoding="utf-8")
            self.assertIn(f"{fact}: true", role_text, role)

    def test_playbooks_do_not_contain_intentionally_destructive_operations(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in ANSIBLE_ROOT.rglob("*.yml"))
        for forbidden in ("down -v", "volume prune", "delete pvc", "stonith-enabled=false", "--insecure", "--remove-orphans"):
            self.assertNotIn(forbidden, content.lower())
        self.assertNotIn("ansible.builtin.shell", content)

    def test_provider_digest_stat_checks_use_sha256(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in ANSIBLE_ROOT.rglob("*.yml"))
        self.assertNotRegex(content, r"get_checksum: true(?!\s+checksum_algorithm: sha256)")

    def test_provider_definitions_require_safe_file_identity(self) -> None:
        provider = "\n".join(
            (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks" / name).read_text(encoding="utf-8")
            for name in ("raw.yml", "podman-quadlet.yml", "docker.yml", "docker-swarm.yml", "verify-bundle.yml")
        )
        self.assertGreaterEqual(provider.count("stat.uid | int == 0"), 6)
        self.assertGreaterEqual(provider.count("stat.gid | int == 0"), 6)
        self.assertGreaterEqual(provider.count("stat.mode == '0644'"), 6)
