from __future__ import annotations

import re
import unittest
from pathlib import Path


ANSIBLE_ROOT = Path(__file__).resolve().parents[1] / "deploy" / "ansible"


def task_block(tasks: str, name: str) -> str:
    match = re.search(rf"(?m)^(?P<indent>[ \t]*)- name: {re.escape(name)}$", tasks)
    if match is None:
        raise ValueError(f"missing Ansible task: {name}")
    next_task = re.search(rf"(?m)^{re.escape(match.group('indent'))}- name: ", tasks[match.end():])
    end = match.end() + next_task.start() if next_task else len(tasks)
    return tasks[match.start():end]


class KubernetesApplyRolloutTests(unittest.TestCase):
    def test_apply_must_wait_for_named_rollout_before_release_record(self) -> None:
        provider = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        provider_main = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/main.yml").read_text(encoding="utf-8")
        site = (ANSIBLE_ROOT / "site.yml").read_text(encoding="utf-8")

        apply_name = "Apply the reviewed product Kustomize bundle"
        rollout_name = "Require the named Kubernetes deployment rollout to complete"
        live_read_name = "Read the live named Kubernetes deployment after rollout"
        live_gate_name = "Require the live Kubernetes deployment to match the reviewed image set and current generation"
        self.assertLess(provider.index("- name: Select the reviewed named Kubernetes deployment"), provider.index(f"- name: {apply_name}"))
        self.assertLess(provider.index(f"- name: {apply_name}"), provider.index(f"- name: {rollout_name}"))
        self.assertLess(provider.index(f"- name: {rollout_name}"), provider.index(f"- name: {live_read_name}"))
        self.assertLess(provider.index(f"- name: {live_read_name}"), provider.index(f"- name: {live_gate_name}"))

        apply_task = task_block(provider, apply_name)
        rollout_task = task_block(provider, rollout_name)
        live_read_task = task_block(provider, live_read_name)
        live_gate_task = task_block(provider, live_gate_name)
        self.assertIn("archiveweaver_provider_kubectl_argv + ['-n', archiveweaver_namespace, 'apply', '-f', '-']", apply_task)
        self.assertIn("stdin: \"{{ archiveweaver_provider_kustomize_render.stdout }}\"", apply_task)
        self.assertIn("stdin_add_newline: false", apply_task)
        self.assertIn("archiveweaver_provider_kubectl_argv + ['-n', archiveweaver_namespace,", rollout_task)
        self.assertIn("'rollout', 'status', 'deployment/' + archiveweaver_solution_id, '--timeout=300s'", rollout_task)
        self.assertIn("archiveweaver_provider_kubectl_argv + ['-n', archiveweaver_namespace,", live_read_task)
        self.assertIn("'get', 'deployment/' + archiveweaver_solution_id, '-o', 'json'", live_read_task)
        self.assertIn("changed_when: false", rollout_task)
        for task in (rollout_task, live_read_task, live_gate_task):
            self.assertIn("- not ansible_check_mode | bool", task)
            self.assertIn("inventory_hostname == (groups['archiveweaver_control'] | default([inventory_hostname]))[0]", task)
            self.assertNotIn("ignore_errors:", task)
            self.assertNotIn("failed_when: false", task)
            self.assertNotIn("check_mode: false", task)

        self.assertIn("ansible.builtin.include_tasks: kubernetes.yml", provider_main)
        self.assertLess(site.index("role: archiveweaver_provider"), site.index("tasks_from: record-release"))
        independent = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/verify-bundle.yml").read_text(encoding="utf-8")
        self.assertIn("Read all live Kubernetes workloads during independent verification", independent)
        self.assertIn("Compare independent live Kubernetes workloads with the reviewed bundle", independent)
        self.assertIn("archiveweaver_provider_verify_live_workload_result.rc == 0", independent)
        self.assertIn("not ansible_check_mode | bool", task_block(site, "Record the converged release after provider handlers complete"))

    def test_live_deployment_gate_checks_reviewed_identity_and_converged_generation(self) -> None:
        provider = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        select_task = task_block(provider, "Select the reviewed named Kubernetes deployment")
        count_task = task_block(provider, "Require exactly one reviewed named Kubernetes deployment")
        namespace_task = task_block(provider, "Bind the reviewed Kubernetes deployment to the selected namespace")
        gate = task_block(provider, "Require the live Kubernetes deployment to match the reviewed image set and current generation")

        for binding in ("from_yaml_all", "apps/v1", "Deployment", "archiveweaver_solution_id"):
            self.assertIn(binding, select_task)
        self.assertIn("archiveweaver_provider_expected_named_deployments | length == 1", count_task)
        self.assertIn("metadata.namespace | default(archiveweaver_namespace, true)", namespace_task)
        self.assertIn("spec.template.spec.containers | length > 0", namespace_task)
        self.assertIn("spec.replicas | default(1) | int) > 0", namespace_task)

        for binding in (
            "metadata.name == archiveweaver_solution_id",
            "metadata.namespace == archiveweaver_namespace",
            "map(attribute='name')",
            "map(attribute='image')",
            "status.observedGeneration",
            "metadata.generation",
            "status.replicas",
            "status.updatedReplicas",
            "status.readyReplicas",
            "status.availableReplicas",
            "spec.replicas | int) > 0",
        ):
            self.assertIn(binding, gate)
        self.assertIn("spec.initContainers | default([], true)", gate)
        self.assertIn("status.replicas | default(0) | int) == (archiveweaver_provider_live_deployment.spec.replicas | int)", gate)
        self.assertIn("status.updatedReplicas | default(0) | int) == (archiveweaver_provider_live_deployment.spec.replicas | int)", gate)

    def test_every_namespaced_workload_image_is_checked_before_release_record(self) -> None:
        provider = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        site = (ANSIBLE_ROOT / "site.yml").read_text(encoding="utf-8")
        read_name = "Read all live namespaced Kubernetes workloads after apply"
        verify_name = "Verify every live Kubernetes workload against the reviewed model"
        gate_name = "Require all live Kubernetes workload images to match the reviewed release"
        self.assertLess(provider.index("Apply the reviewed product Kustomize bundle"), provider.index(read_name))
        self.assertLess(provider.index(read_name), provider.index(verify_name))
        self.assertLess(provider.index(verify_name), provider.index(gate_name))
        self.assertIn("deployments,statefulsets,jobs,cronjobs", task_block(provider, read_name))
        verify = task_block(provider, verify_name)
        self.assertIn("verify-live-kubernetes-workloads.py", verify)
        self.assertIn("archiveweaver_provider_kustomize_render.stdout", verify)
        self.assertIn("archiveweaver_provider_live_workloads.stdout | from_json", verify)
        self.assertIn("stdin_add_newline: false", verify)
        self.assertIn("no_log: true", verify)
        self.assertIn("archiveweaver_provider_live_workload_verification.rc == 0", task_block(provider, gate_name))
        self.assertLess(site.index("role: archiveweaver_provider"), site.index("tasks_from: record-release"))

    def test_every_rendered_controller_rolls_out_and_job_completes(self) -> None:
        provider = (ANSIBLE_ROOT / "roles/archiveweaver_provider/tasks/kubernetes.yml").read_text(encoding="utf-8")
        selected = task_block(provider, "Select every reviewed Kubernetes controller and one-shot job")
        controllers = task_block(provider, "Wait for every reviewed Deployment and StatefulSet rollout")
        jobs = task_block(provider, "Wait for every reviewed Kubernetes Job to complete")
        self.assertIn("['Deployment', 'StatefulSet']", selected)
        self.assertIn("'Job'", selected)
        self.assertIn("archiveweaver_provider_expected_replicated_workloads", controllers)
        self.assertIn("'rollout', 'status'", controllers)
        self.assertIn("'--timeout=300s'", controllers)
        self.assertIn("archiveweaver_provider_expected_jobs", jobs)
        self.assertIn("'wait', '--for=condition=complete'", jobs)
        self.assertIn("'--timeout=300s'", jobs)
        for step in (controllers, jobs):
            self.assertIn("- not ansible_check_mode | bool", step)
            self.assertIn("changed_when: false", step)
            self.assertIn("no_log: true", step)
        self.assertLess(provider.index("Apply the reviewed product Kustomize bundle"), provider.index("Wait for every reviewed Deployment and StatefulSet rollout"))
        self.assertLess(provider.index("Wait for every reviewed Kubernetes Job to complete"), provider.index("Read all live namespaced Kubernetes workloads after apply"))


if __name__ == "__main__":
    unittest.main()
