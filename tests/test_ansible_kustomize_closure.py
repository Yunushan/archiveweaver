"""Contract checks for the remote Kustomize closure and live-resource gates."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "deploy/ansible/roles/archiveweaver_provider/tasks/kubernetes.yml"
VERIFY = ROOT / "deploy/ansible/roles/archiveweaver_provider/tasks/verify-bundle.yml"
TREE = ROOT / "deploy/ansible/roles/archiveweaver_provider/tasks/verify-kustomize-tree.yml"


def tasks(path: Path) -> list[dict[str, Any]]:
    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(content, list)
    return content


def task_by_name(path: Path, name: str) -> dict[str, Any]:
    for task in tasks(path):
        if task.get("name") == name:
            return task
    raise AssertionError(f"missing task {name}: {path}")


class KustomizeClosureContractTests(unittest.TestCase):
    def test_provider_rehashes_before_render_after_render_and_before_apply(self) -> None:
        names = [task["name"] for task in tasks(PROVIDER)]
        ordered = [
            "Require the reviewed Kustomize bundle digest",
            "Require a protected local-only Kustomize closure before rendering",
            "Render the staged product Kustomize bundle read-only",
            "Rehash the protected Kustomize closure after rendering",
            "Validate the rendered Paperless RKE2 product model before apply",
            "Require signed image coverage before Kubernetes apply",
            "Rehash the protected Kustomize closure immediately before apply",
            "Require server admission of the exact rendered Kubernetes model before apply",
            "Apply the reviewed product Kustomize bundle",
        ]
        self.assertEqual([names.index(name) for name in ordered], sorted(names.index(name) for name in ordered))
        for name in ordered:
            if "closure" in name:
                self.assertEqual(task_by_name(PROVIDER, name)["ansible.builtin.include_tasks"], "verify-kustomize-tree.yml")

    def test_verification_rehashes_around_independent_render(self) -> None:
        names = [task["name"] for task in tasks(VERIFY)]
        ordered = [
            "Require the verified Kustomize bundle to match its release digest",
            "Require a protected local-only Kustomize closure during verification",
            "Re-render the verified Kustomize bundle read-only",
            "Rehash the protected Kustomize closure after verification render",
            "Validate the independently rendered Paperless RKE2 product model",
            "Require signed image coverage during Kubernetes verification",
            "Require every live Kubernetes resource to match the verified model",
        ]
        self.assertEqual([names.index(name) for name in ordered], sorted(names.index(name) for name in ordered))

    def test_closure_reads_remote_bytes_and_validates_on_controller(self) -> None:
        entries = tasks(TREE)
        names = [entry["name"] for entry in entries]
        self.assertLess(names.index("Hash every staged Kustomize input file independently"), names.index("Read the observed Kustomize file bytes for closure and digest validation"))
        self.assertLess(names.index("Read the observed Kustomize file bytes for closure and digest validation"), names.index("Require an immutable local-only Kustomize input closure"))
        validator = task_by_name(TREE, "Require an immutable local-only Kustomize input closure")
        command = validator["ansible.builtin.command"]
        self.assertIn("verify-kustomize-bundle.py", command["argv"][1])
        self.assertIn("archiveweaver_kustomize_bundle_sha256", command["argv"][2])
        self.assertIn("archiveweaver_provider_kustomize_tree_slurped.results", command["stdin"])
        self.assertEqual(validator["delegate_to"], "localhost")
        self.assertTrue(validator["no_log"])
        for path, name in (
            (PROVIDER, "Hash every staged Kustomize file for the release binding"),
            (VERIFY, "Hash the verified Kustomize file set"),
            (TREE, "Hash every staged Kustomize input file independently"),
        ):
            self.assertTrue(task_by_name(path, name)["ansible.builtin.find"]["get_checksum"])

    def test_paperless_model_validator_uses_exact_rendered_bytes(self) -> None:
        for path, name, rendered in (
            (PROVIDER, "Validate the rendered Paperless RKE2 product model before apply", "archiveweaver_provider_kustomize_render.stdout"),
            (VERIFY, "Validate the independently rendered Paperless RKE2 product model", "archiveweaver_provider_verify_kustomize_render.stdout"),
        ):
            with self.subTest(path=path):
                task = task_by_name(path, name)
                command = task["ansible.builtin.command"]
                self.assertIn("verify-paperless-rke2-model.py", command["argv"][1])
                self.assertIn(rendered, command["stdin"])
                self.assertIs(command["stdin_add_newline"], False)
                self.assertEqual(task["delegate_to"], "localhost")
                self.assertIn("archiveweaver_solution_id == 'paperless-ngx'", task["when"])
                self.assertTrue(task["no_log"])

    def test_apply_and_verification_diff_exact_cached_bytes_fail_closed(self) -> None:
        for path, name, rendered in (
            (PROVIDER, "Require every applied Kubernetes resource to match the reviewed model", "archiveweaver_provider_kustomize_render.stdout"),
            (VERIFY, "Require every live Kubernetes resource to match the verified model", "archiveweaver_provider_verify_kustomize_render.stdout"),
        ):
            with self.subTest(path=path):
                task = task_by_name(path, name)
                command = task["ansible.builtin.command"]
                self.assertIn("'diff', '--show-secrets', '-f', '-'", command["argv"])
                self.assertIn(rendered, command["stdin"])
                self.assertIs(command["stdin_add_newline"], False)
                self.assertEqual(task["environment"]["KUBECTL_EXTERNAL_DIFF"], "/usr/bin/diff")
                self.assertIn("rc != 0", task["failed_when"])
                self.assertTrue(task["no_log"])

    def test_server_dry_run_checks_exact_cached_bytes_before_apply(self) -> None:
        task = task_by_name(PROVIDER, "Require server admission of the exact rendered Kubernetes model before apply")
        command = task["ansible.builtin.command"]
        self.assertIn("'apply', '--dry-run=server', '-f', '-'", command["argv"])
        self.assertIn("archiveweaver_provider_kustomize_render.stdout", command["stdin"])
        self.assertIs(command["stdin_add_newline"], False)
        self.assertIn("rc != 0", task["failed_when"])
        self.assertIn("not ansible_check_mode", " ".join(task["when"]))
        self.assertTrue(task["no_log"])


if __name__ == "__main__":
    unittest.main()
