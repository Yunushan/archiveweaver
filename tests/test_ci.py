from __future__ import annotations

import copy
import hashlib
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class CIWorkflowTests(unittest.TestCase):
    def test_github_actions_are_pinned_to_immutable_commit_shas(self) -> None:
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        uses_lines = [
            line.strip()
            for workflow_path in workflows
            for line in workflow_path.read_text(encoding="utf-8").splitlines()
            if "uses:" in line
        ]
        self.assertTrue(uses_lines)
        for line in uses_lines:
            self.assertRegex(line, r"uses:\s+[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}(?:\s+#.*)?$")
            self.assertNotRegex(line, r"@[vV][0-9]")

    def test_security_and_release_workflows_require_supply_chain_controls(self) -> None:
        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("github/codeql-action/init@", security)
        self.assertIn("bandit==1.9.4", security)
        self.assertIn("pip-audit==2.10.1", security)
        self.assertIn("--severity-level medium", security)
        self.assertIn("pip-audit --no-deps --disable-pip -r deploy/ansible/requirements.txt --strict", security)
        self.assertIn("anchore/sbom-action@", release)
        self.assertIn("format: spdx-json", release)
        self.assertIn("sigstore/gh-action-sigstore-python@", release)
        self.assertIn("persist-credentials: false", release)
        self.assertIn("inputs: dist/*", release)
        self.assertIn("verify: true", release)
        self.assertIn("verify-cert-identity:", release)
        self.assertIn("verify-oidc-issuer: https://token.actions.githubusercontent.com", release)
        self.assertIn("actions/attest-build-provenance@", release)
        self.assertIn("attestations: write", release)
        self.assertIn("Require release tag to match package version", release)

    def test_dependabot_covers_runtime_and_automation_dependencies(self) -> None:
        dependabot = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: github-actions", dependabot)
        self.assertIn("package-ecosystem: pip", dependabot)
        self.assertIn("directory: /deploy/ansible", dependabot)
        self.assertIn("directory: /deploy/ansible/execution-environment", dependabot)

    def test_controller_contract_verifies_signed_source_identity(self) -> None:
        workflow = (ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8")
        controller_readme = (ROOT / "deploy/ansible/controller/README.md").read_text(encoding="utf-8")
        verifier = ROOT / "scripts/verify-source-identity.sh"
        manifest_verifier = ROOT / "scripts/verify-readiness-manifest.py"
        contract_validator = ROOT / "scripts/validate-controller-contract.py"
        operational_runner = ROOT / "scripts/run-ansible-operational.sh"
        self.assertTrue(verifier.is_file())
        self.assertTrue(manifest_verifier.is_file())
        self.assertTrue(contract_validator.is_file())
        self.assertTrue(operational_runner.is_file())
        self.assertIn("source-integrity", workflow)
        self.assertIn("verify-source-identity.sh", workflow)
        self.assertIn("ARCHIVEWEAVER_IMMUTABLE_REF", workflow)
        self.assertIn("ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS", workflow)
        self.assertIn("ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", workflow)
        self.assertIn("scripts/verify-readiness-manifest.py", workflow)
        self.assertIn("product-certification", workflow)
        self.assertIn("backup-and-restore-gate", workflow)
        self.assertIn("source_verification: signed-commit-and-clean-checkout", workflow)
        self.assertIn("required_inventory: true", workflow)
        for inventory in (
            "inventory/production/hosts.yml",
            "inventory/staging/hosts.yml",
            "inventory/restore/hosts.yml",
        ):
            self.assertIn(inventory, workflow)
        self.assertIn("key_prefix: archiveweaver_", workflow)
        self.assertIn("reject_sources:", workflow)
        self.assertIn("clear_ambient_ansible: true", workflow)
        self.assertIn("clear_python_import_path: true", workflow)
        self.assertIn("allowed_options:", workflow)
        self.assertIn("--syntax-check", workflow)
        self.assertIn("archiveweaver_serial", workflow)
        self.assertLess(workflow.index("- id: source-integrity"), workflow.index("- id: catalog-and-tests"))
        self.assertIn("verify-source-identity.sh", controller_readme)
        self.assertIn("git ls-files --others --exclude-standard -z", verifier.read_text(encoding="utf-8"))
        self.assertIn("GIT_OPTIONAL_LOCKS=0", verifier.read_text(encoding="utf-8"))
        self.assertIn("{40}|[0-9a-fA-F]{64}", verifier.read_text(encoding="utf-8"))
        self.assertIn("VALIDSIG", verifier.read_text(encoding="utf-8"))
        self.assertIn("ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS", verifier.read_text(encoding="utf-8"))
        self.assertIn("git ls-files --others --ignored --exclude-standard -z", verifier.read_text(encoding="utf-8"))
        self.assertIn("is_allowed_operator_path", verifier.read_text(encoding="utf-8"))
        self.assertIn("operator_path_is_safe", verifier.read_text(encoding="utf-8"))
        self.assertIn("! -L", verifier.read_text(encoding="utf-8"))
        self.assertIn("release-manifest-restore.json", verifier.read_text(encoding="utf-8"))
        runner = operational_runner.read_text(encoding="utf-8")
        self.assertIn("--start-at-task", runner)
        self.assertIn("--step", runner)
        self.assertIn("--ask-pass", runner)
        self.assertIn("--key-file", runner)
        self.assertIn("-b", runner)
        self.assertIn("-k", runner)
        self.assertIn("-K", runner)
        self.assertIn("--limit", runner)
        self.assertIn("--tags", runner)
        self.assertIn("--skip-tags", runner)
        self.assertIn("--step=*", runner)
        self.assertIn("--vault-id", runner)
        self.assertIn("--private-key", runner)
        self.assertIn("--connection", runner)
        self.assertIn("--module-path", runner)
        self.assertIn("--forks", runner)
        self.assertIn("--timeout", runner)
        self.assertIn("--inventory-file", runner)
        self.assertIn('export ANSIBLE_CONFIG="${ansible_root}/ansible.cfg"', runner)
        self.assertIn('export ANSIBLE_ROLES_PATH="${ansible_root}/roles"', runner)
        self.assertIn("ANSIBLE_FILTER_PLUGINS", runner)
        self.assertIn("ANSIBLE_CONNECTION", runner)
        self.assertIn("PYTHONPATH", runner)
        self.assertIn("PYTHONHOME", runner)
        self.assertIn('exec ansible-playbook "$@" "${playbook}"', runner)
        contract_result = subprocess.run(
            [sys.executable, str(contract_validator)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(contract_result.returncode, 0, contract_result.stderr)

    def test_controller_contract_rejects_runner_impersonation(self) -> None:
        validator = runpy.run_path(str(ROOT / "scripts/validate-controller-contract.py"))
        contract = yaml.safe_load((ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8"))
        tampered = copy.deepcopy(contract)
        for item in tampered["workflow"]:
            if item["id"] == "production-apply":
                item["command"] = "echo ../../scripts/run-ansible-operational.sh site.yml && ansible-playbook site.yml"
                break
        errors = validator["validate"](tampered)
        self.assertTrue(any("must not invoke raw ansible-playbook" in error for error in errors))

    def test_controller_contract_rejects_unbound_inventory(self) -> None:
        validator = runpy.run_path(str(ROOT / "scripts/validate-controller-contract.py"))
        contract = yaml.safe_load((ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8"))
        tampered = copy.deepcopy(contract)
        for item in tampered["workflow"]:
            if item["id"] == "production-apply":
                item["command"] = item["command"].replace("-i inventory/production/hosts.yml", "-i /tmp/untrusted-inventory")
                break
        errors = validator["validate"](tampered)
        self.assertTrue(any("approved inventory" in error for error in errors))

    def test_controller_contract_rejects_runner_path_and_shell_chaining(self) -> None:
        validator = runpy.run_path(str(ROOT / "scripts/validate-controller-contract.py"))
        contract = yaml.safe_load((ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8"))

        lookalike = copy.deepcopy(contract)
        for item in lookalike["workflow"]:
            if item["id"] == "production-apply":
                item["command"] = item["command"].replace(
                    "../../scripts/run-ansible-operational.sh",
                    "../../untrusted/scripts/run-ansible-operational.sh",
                )
                break
        errors = validator["validate"](lookalike)
        self.assertTrue(any("exactly one approved operational runner token" in error for error in errors))

        chained = copy.deepcopy(contract)
        for item in chained["workflow"]:
            if item["id"] == "production-apply":
                item["command"] += " && echo unapproved"
                break
        errors = validator["validate"](chained)
        self.assertTrue(any("shell control or substitution markers" in error for error in errors))

        extra_playbook = copy.deepcopy(contract)
        for item in extra_playbook["workflow"]:
            if item["id"] == "production-apply":
                item["command"] += " -- ../unapproved.yml"
                break
        errors = validator["validate"](extra_playbook)
        self.assertTrue(any("unapproved operational argument" in error for error in errors))

    def test_readiness_manifest_binding_verifier_accepts_only_exact_bytes(self) -> None:
        manifest = ROOT / "deploy/ansible/release-manifest.example.json"
        verifier = ROOT / "scripts/verify-readiness-manifest.py"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        accepted = subprocess.run(
            [sys.executable, str(verifier), str(manifest), digest],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        rejected = subprocess.run(
            [sys.executable, str(verifier), str(manifest), "0" * 64],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("does not match", rejected.stderr)

    def test_ci_rejects_generated_catalog_drift(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.2", workflow)
        self.assertIn("python scripts/generate_catalog.py", workflow)
        self.assertIn("git diff --exit-code", workflow)
        self.assertIn("python -m pip install --disable-pip-version-check --no-input --no-deps .", workflow)
        self.assertIn("bash tests/test-operational-runner.sh", workflow)
        self.assertIn("bash tests/test-execution-environment.sh", workflow)
        self.assertIn("bash -n scripts/*.sh tests/*.sh", workflow)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("test: validate controller-validate", makefile)
        self.assertIn("bash tests/test-operational-runner.sh", makefile)
        self.assertIn("bash tests/test-execution-environment.sh", makefile)

    def test_python_support_matrix_matches_package_metadata(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        core_versions = workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(core_versions, ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"])
        ansible_versions = workflow["jobs"]["ansible"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(ansible_versions, ["3.13", "3.14"])

        for job_name in ("test", "ansible"):
            setup_python = next(
                step
                for step in workflow["jobs"][job_name]["steps"]
                if step.get("uses", "").startswith("actions/setup-python@")
            )
            self.assertIs(setup_python["with"]["allow-prereleases"], True)

        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.9"', metadata)
        for version in core_versions:
            self.assertIn(f'"Programming Language :: Python :: {version}"', metadata)
