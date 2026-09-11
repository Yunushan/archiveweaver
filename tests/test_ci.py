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
    def test_repository_governance_contracts_are_present(self) -> None:
        required = (
            ".gitattributes",
            "CHANGELOG.md",
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "SUPPORT.md",
            ".github/CODEOWNERS",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
        )
        for relative in required:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertTrue(path.read_text(encoding="utf-8").strip(), relative)
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
        self.assertIn("/.github/workflows/", codeowners)
        self.assertIn("/deploy/ansible/", codeowners)
        self.assertIn("/requirements/", codeowners)
        support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
        self.assertIn("does not provide a commercial support contract", support)
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf", attributes)

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

    def test_github_jobs_pin_the_runner_os_family(self) -> None:
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        jobs = 0
        for workflow_path in workflows:
            workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
            for job in workflow.get("jobs", {}).values():
                jobs += 1
                self.assertEqual(job.get("runs-on"), "ubuntu-24.04", workflow_path.name)
        self.assertGreater(jobs, 0)

    def test_security_and_release_workflows_require_supply_chain_controls(self) -> None:
        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        scorecards = (ROOT / ".github/workflows/scorecards.yml").read_text(
            encoding="utf-8"
        )
        codeql_config = (ROOT / ".github/codeql/codeql-config.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        release_publisher = (ROOT / "scripts/publish-github-release.py").read_text(
            encoding="utf-8"
        )
        release_tools_input = (ROOT / "requirements/release-tools.in").read_text(
            encoding="utf-8"
        )
        self.assertIn("github/codeql-action/init@", security)
        self.assertIn("config-file: ./.github/codeql/codeql-config.yml", security)
        self.assertIn("paths-ignore:", codeql_config)
        self.assertIn("  - tests", codeql_config)
        self.assertIn("bandit==1.9.4", release_tools_input)
        self.assertIn("pip-audit==2.10.1", release_tools_input)
        self.assertIn("-r requirements/release-tools.txt", security)
        self.assertIn("--require-hashes --only-binary=:all:", security)
        self.assertIn("python scripts/validate-upstream-repositories.py", security)
        self.assertIn("--severity-level medium", security)
        self.assertIn("pip-audit --no-deps --disable-pip -r deploy/ansible/requirements.txt --strict", security)
        self.assertIn(
            "pip-audit --no-deps --disable-pip -r requirements/release-tools.txt --strict",
            security,
        )
        self.assertIn("actions/dependency-review-action@", security)
        self.assertIn("fail-on-severity: moderate", security)
        self.assertIn("fail-on-scopes: runtime, development", security)
        scorecard_workflow = yaml.safe_load(scorecards)
        scorecard_job = scorecard_workflow["jobs"]["analysis"]
        self.assertEqual(scorecard_workflow["permissions"], "read-all")
        self.assertEqual(
            scorecard_job["permissions"],
            {
                "contents": "read",
                "id-token": "write",
                "security-events": "write",
            },
        )
        self.assertEqual(scorecard_job["timeout-minutes"], 20)
        self.assertIn("ossf/scorecard-action@", scorecards)
        self.assertIn("publish_results: true", scorecards)
        self.assertIn("results_format: sarif", scorecards)
        self.assertIn("file_mode: git", scorecards)
        self.assertIn("github/codeql-action/upload-sarif@", scorecards)
        self.assertIn("persist-credentials: false", scorecards)
        self.assertIn("anchore/sbom-action@", release)
        self.assertIn("format: spdx-json", release)
        self.assertIn("upload-artifact: false", release)
        self.assertIn("upload-release-assets: false", release)
        self.assertIn("spdx-tools==0.8.5", release_tools_input)
        self.assertIn("-r requirements/release-tools.txt", release)
        self.assertIn("--require-hashes --only-binary=:all:", release)
        self.assertIn("python -m build --no-isolation", release)
        self.assertIn("--no-build-isolation", release)
        self.assertIn("python scripts/generate-ansible-sbom.py", release)
        self.assertIn("python scripts/generate-ansible-sbom.py --check", release)
        self.assertIn("python -m spdx_tools.spdx.clitools.pyspdxtools", release)
        self.assertIn("-i archiveweaver-ansible-controller.spdx.json", release)
        self.assertIn("archiveweaver-validated-sboms", release)
        self.assertIn("sha256sum dist/* archiveweaver.spdx.json", release)
        self.assertIn(
            "archiveweaver-ee.grype.json github-production-controls.json > SHA256SUMS",
            release,
        )
        self.assertIn("sigstore/gh-action-sigstore-python@", release)
        self.assertIn("persist-credentials: false", release)
        self.assertIn("inputs: |", release)
        self.assertIn("archiveweaver.spdx.json.sigstore.json", release)
        self.assertIn(
            "archiveweaver-ansible-controller.spdx.json.sigstore.json", release
        )
        self.assertIn("SHA256SUMS.sigstore.json", release)
        self.assertIn("verify: true", release)
        self.assertIn("verify-cert-identity:", release)
        self.assertIn("verify-oidc-issuer: https://token.actions.githubusercontent.com", release)
        self.assertIn("actions/attest-build-provenance@", release)
        self.assertIn("subject-path: |", release)
        self.assertIn("digest-mismatch: error", release)
        self.assertIn("attestations: write", release)
        self.assertIn("Require release tag to match package version", release)
        self.assertIn("Require a verified annotated release tag bound to this commit", release)
        self.assertIn("release tags must be signed annotated tags", release)
        self.assertIn(".verification.verified", release)
        self.assertIn("Publish the immutable tagged release", release)
        self.assertIn(
            "python3 .release-publisher/publish-github-release.py", release
        )
        self.assertRegex(
            release_publisher,
            r'_run_gh\(\s*\(\s*"release",\s*"create",',
        )
        self.assertIn("repos/{repository}/immutable-releases", release_publisher)
        self.assertIn("ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN", release_publisher)
        self.assertIn("remote.get(\"digest\") != local.digest", release_publisher)
        self.assertIn("release.get(\"immutable\") is not True", release_publisher)
        self.assertNotIn("--clobber", release_publisher)
        self.assertIn("--verify-tag", release_publisher)
        self.assertIn("contents: write", release)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/')", release)
        release_workflow = yaml.safe_load(release)
        validate_job = release_workflow["jobs"]["validate"]
        execution_environment_job = release_workflow["jobs"]["execution-environment"]
        package_job = release_workflow["jobs"]["package"]
        self.assertEqual(validate_job["permissions"], {"contents": "read"})
        self.assertEqual(execution_environment_job["needs"], "validate")
        self.assertEqual(
            execution_environment_job["if"],
            "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        )
        self.assertEqual(
            execution_environment_job["permissions"], {"contents": "read"}
        )
        self.assertEqual(execution_environment_job["environment"], "release")
        self.assertIn(
            "ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE",
            execution_environment_job["env"]["ANSIBLE_EE_BASE_IMAGE"],
        )
        self.assertIn(
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON",
            execution_environment_job["env"]["ARCHIVEWEAVER_RELEASE_ACTORS_JSON"],
        )
        self.assertEqual(package_job["needs"], ["validate", "execution-environment"])
        self.assertEqual(
            package_job["if"],
            "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        )
        self.assertEqual(package_job["environment"], "release")
        self.assertEqual(package_job["permissions"]["actions"], "read")
        self.assertEqual(package_job["permissions"]["packages"], "write")
        self.assertIn(
            "ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE",
            package_job["env"]["ANSIBLE_EE_BASE_IMAGE"],
        )
        self.assertIn(
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON",
            package_job["env"]["ARCHIVEWEAVER_RELEASE_ACTORS_JSON"],
        )
        self.assertFalse(
            any("actions/checkout@" in step.get("uses", "") for step in package_job["steps"])
        )
        self.assertTrue(
            any("actions/download-artifact@" in step.get("uses", "") for step in package_job["steps"])
        )
        downloaded_artifacts = {
            step["with"]["name"]
            for step in package_job["steps"]
            if "actions/download-artifact@" in step.get("uses", "")
        }
        self.assertEqual(
            downloaded_artifacts,
            {
                "archiveweaver-validated-distributions",
                "archiveweaver-validated-sboms",
                "archiveweaver-validated-execution-environment",
                "archiveweaver-validated-release-publisher",
            },
        )
        uploaded_artifacts = {
            step["with"]["name"]
            for step in validate_job["steps"]
            if "actions/upload-artifact@" in step.get("uses", "")
        }
        self.assertIn("archiveweaver-validated-release-publisher", uploaded_artifacts)
        helper_upload = next(
            step
            for step in validate_job["steps"]
            if step.get("with", {}).get("name")
            == "archiveweaver-validated-release-publisher"
        )
        self.assertIn(
            "scripts/audit-github-production-controls.py",
            helper_upload["with"]["path"],
        )
        self.assertGreaterEqual(release.count("verify-release-actors.py"), 3)
        self.assertGreaterEqual(release.count("github.triggering_actor"), 2)
        self.assertIn("Require the approved tag-push and rerun actors", release)
        self.assertTrue((ROOT / "scripts/audit-github-production-controls.py").is_file())
        self.assertIn("make github-audit", (ROOT / "Makefile").read_text(encoding="utf-8"))
        self.assertIn("schema_version\": 2", release)
        self.assertIn("execution_environment_marker", release)
        self.assertIn(".runtime.command == [\"bash\"]", release)
        self.assertIn(".runtime.entrypoint == [\"dumb-init\", \"--\"]", release)
        self.assertIn(".runtime.user == \"65532:65532\"", release)
        self.assertIn(".runtime.working_directory == \"/runner\"", release)
        self.assertIn("docker run --rm \"${ANSIBLE_EE_LOCAL_TAG}\"", release)
        self.assertFalse(
            any(
                "anchore/sbom-action@" in step.get("uses", "")
                for step in package_job["steps"]
            )
        )
        self.assertTrue(
            any(
                "anchore/sbom-action@" in step.get("uses", "")
                for step in validate_job["steps"]
            )
        )
        self.assertTrue(
            any(
                "anchore/sbom-action@" in step.get("uses", "")
                for step in execution_environment_job["steps"]
            )
        )
        self.assertTrue(
            any(
                "anchore/scan-action@" in step.get("uses", "")
                for step in execution_environment_job["steps"]
            )
        )
        self.assertIn(
            "bash scripts/build-ansible-execution-environment.sh", release
        )
        self.assertIn("--source-revision \"${GITHUB_SHA}\"", release)
        self.assertIn("sigstore/cosign-installer@", release)
        self.assertIn("cosign verify-attestation", release)
        self.assertIn("cosign sign-blob --yes", release)
        self.assertIn("cosign verify-blob", release)
        self.assertIn("archiveweaver-ee.publication.json", release)
        self.assertIn("docker manifest inspect \"${image_name}@${digest}\"", release)
        self.assertIn("docker buildx imagetools inspect --raw", release)
        self.assertIn("existing_config_digest", release)
        self.assertIn("manifest unknown|not found", release)
        self.assertIn("unable to determine whether the controller image tag already exists", release)
        self.assertIn('"${existing_config_digest}" != "${local_image_id}"', release)
        self.assertIn('"${published_config_digest}" != "${local_image_id}"', release)
        self.assertIn("refusing to overwrite an existing controller image tag with different content", release)
        self.assertIn("reusing the existing tag because it contains the exact validated image", release)
        self.assertIn("subject-digest: ${{ steps.publish-ee.outputs.digest }}", release)
        step_names = [step.get("name", "") for step in package_job["steps"]]
        hosted_audit_name = (
            "Require all hosted production controls immediately before publication"
        )
        hosted_audit = next(
            step for step in package_job["steps"] if step.get("name") == hosted_audit_name
        )
        self.assertEqual(
            hosted_audit["env"]["GH_TOKEN"],
            "${{ secrets.ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN }}",
        )
        self.assertIn("--source-revision \"${GITHUB_SHA}\"", hosted_audit["run"])
        self.assertIn("github-production-controls.json", release)
        self.assertLess(
            step_names.index(hosted_audit_name),
            step_names.index("Publish the immutable controller image"),
        )
        self.assertLess(
            step_names.index("Sign and verify the immutable image publication record"),
            step_names.index("Upload the complete release evidence set"),
        )
        self.assertLess(
            step_names.index("Upload the complete release evidence set"),
            step_names.index("Publish the immutable tagged release"),
        )

    def test_dependabot_covers_runtime_and_automation_dependencies(self) -> None:
        dependabot_path = ROOT / ".github/dependabot.yml"
        dependabot = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: github-actions", dependabot)
        self.assertIn("package-ecosystem: pip", dependabot)
        self.assertIn("directory: /deploy/ansible", dependabot)
        self.assertIn("directory: /deploy/ansible/execution-environment", dependabot)
        self.assertIn("directory: /requirements", dependabot)
        configuration = yaml.safe_load(dependabot)
        self.assertEqual(len(configuration["updates"]), 5)
        for update in configuration["updates"]:
            self.assertLessEqual(update["open-pull-requests-limit"], 5)
            groups = update.get("groups", {})
            self.assertEqual(len(groups), 1)
            self.assertIn("*", next(iter(groups.values()))["patterns"])

    def test_controller_contract_verifies_signed_source_identity(self) -> None:
        workflow = (ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8")
        controller_readme = (ROOT / "deploy/ansible/controller/README.md").read_text(encoding="utf-8")
        verifier = ROOT / "scripts/verify-source-identity.sh"
        manifest_verifier = ROOT / "scripts/verify-readiness-manifest.py"
        contract_validator = ROOT / "scripts/validate-controller-contract.py"
        operational_runner = ROOT / "scripts/run-ansible-operational.sh"
        extra_vars_allowlist = (
            ROOT / "deploy/ansible/controller/allowed-extra-vars.txt"
        )
        self.assertTrue(verifier.is_file())
        self.assertTrue(manifest_verifier.is_file())
        self.assertTrue(contract_validator.is_file())
        self.assertTrue(operational_runner.is_file())
        self.assertTrue(extra_vars_allowlist.is_file())
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
        self.assertIn("allowed_keys_file: controller/allowed-extra-vars.txt", workflow)
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
        self.assertIn("extra_vars_allowlist", runner)
        self.assertNotIn(
            "archiveweaver_packages_debian",
            extra_vars_allowlist.read_text(encoding="utf-8"),
        )
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

    def test_controller_contract_rejects_unreviewed_extra_var(self) -> None:
        validator = runpy.run_path(
            str(ROOT / "scripts/validate-controller-contract.py")
        )
        contract = yaml.safe_load(
            (ROOT / "deploy/ansible/controller/workflow.yml").read_text(
                encoding="utf-8"
            )
        )
        tampered = copy.deepcopy(contract)
        for item in tampered["workflow"]:
            if item["id"] == "production-apply":
                item["command"] += " -e archiveweaver_unreviewed_variable=true"
                break
        errors = validator["validate"](tampered)
        self.assertTrue(any("outside the reviewed allowlist" in error for error in errors))

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
        release_tools_input = (ROOT / "requirements/release-tools.in").read_text(
            encoding="utf-8"
        )
        self.assertIn("PyYAML==6.0.3", workflow)
        self.assertIn("--require-hashes --only-binary=:all:", workflow)
        self.assertIn("-r deploy/ansible/requirements.txt", workflow)
        self.assertIn("python scripts/generate_catalog.py", workflow)
        self.assertIn("python scripts/validate-yaml.py", workflow)
        self.assertIn("git diff --exit-code", workflow)
        self.assertIn("python -m pip install --disable-pip-version-check --no-input --no-deps .", workflow)
        self.assertIn("ruff==0.15.20", release_tools_input)
        self.assertIn("mypy==1.20.2", release_tools_input)
        self.assertIn("coverage==7.15.1", release_tools_input)
        self.assertGreaterEqual(workflow.count("-r requirements/release-tools.txt"), 2)
        self.assertIn("make quality", workflow)
        self.assertIn("python -m coverage run -m unittest discover -s tests", workflow)
        self.assertIn("python -m coverage report", workflow)
        coverage_configuration = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("fail_under = 90", coverage_configuration)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 5)
        self.assertEqual(workflow.count("timeout-minutes:"), 5)

    def test_ci_validates_the_built_operational_distribution(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        validator = (ROOT / "scripts/validate-installed-distribution.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("python -m build", workflow)
        self.assertIn("-r requirements/release-tools.txt", workflow)
        self.assertIn("python -m build --no-isolation", workflow)
        self.assertIn("--no-build-isolation", workflow)
        self.assertIn("SOURCE_DATE_EPOCH", workflow)
        self.assertIn("python scripts/normalize-sdist.py dist/*.tar.gz", workflow)
        self.assertIn("python scripts/normalize-sdist.py --check dist/*.tar.gz", workflow)
        self.assertIn("cmp dist/*.whl dist-reproducibility/*.whl", workflow)
        self.assertIn("cmp dist/*.tar.gz dist-reproducibility/*.tar.gz", workflow)
        self.assertIn("dist/*.tar.gz", workflow)
        self.assertIn("python scripts/validate-installed-distribution.py", workflow)
        self.assertIn("python scripts/validate-installed-distribution.py", release)
        self.assertIn("SOURCE_DATE_EPOCH", release)
        self.assertIn("python scripts/normalize-sdist.py --check dist/*.tar.gz", release)
        self.assertIn("cmp dist/*.whl dist-reproducibility/*.whl", release)
        self.assertIn("_find_ansible_root", validator)
        self.assertIn("generate-ansible-sbom.py", validator)
        self.assertIn("run-ansible-operational.sh", validator)
        self.assertIn("bash tests/test-operational-runner.sh", workflow)
        self.assertIn("bash tests/test-execution-environment.sh", workflow)
        self.assertIn("bash -n scripts/*.sh tests/*.sh", workflow)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "test: validate controller-validate yaml-validate release-tools-check",
            makefile,
        )
        self.assertIn("python3 scripts/validate-yaml.py", makefile)
        self.assertIn("python3 scripts/generate-ansible-sbom.py", makefile)
        self.assertIn("python3 scripts/compile-release-tools-lock.py --check", makefile)
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
