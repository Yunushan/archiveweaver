from __future__ import annotations

import unittest

from archiveweaver.catalog import Catalog
from archiveweaver.planner import build_plan, node_bucket


class PlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_node_bucket(self) -> None:
        self.assertEqual(node_bucket("1"), "1")
        self.assertEqual(node_bucket("2"), "2")
        self.assertEqual(node_bucket("3"), "3")
        self.assertEqual(node_bucket("7"), "3+")
        self.assertEqual(node_bucket("3+"), "3+")

    def test_three_node_rke2_is_not_blocked(self) -> None:
        plan = build_plan(self.catalog, "paperless-ngx", "rke2", "3", "ubuntu-24.04")
        self.assertNotEqual(plan.status, "blocked")
        self.assertEqual(plan.topology_level, "supported")
        self.assertTrue(any("outside the scheduler" in item for item in plan.warnings))

    def test_three_node_swarm_requires_external_storage(self) -> None:
        plan = build_plan(
            self.catalog,
            "paperless-ngx",
            "docker-swarm",
            "3",
            "ubuntu-24.04",
        )
        self.assertEqual(plan.status, "blocked")
        self.assertFalse(plan.external_storage)
        self.assertTrue(any("shared or replicated" in item for item in plan.blockers))

    def test_three_node_swarm_records_external_storage_approval(self) -> None:
        plan = build_plan(
            self.catalog,
            "paperless-ngx",
            "docker-swarm",
            "3",
            "ubuntu-24.04",
            external_storage=True,
        )
        self.assertNotEqual(plan.status, "blocked")
        self.assertTrue(plan.external_storage)

    def test_two_node_rke2_is_blocked_without_external_state(self) -> None:
        plan = build_plan(self.catalog, "paperless-ngx", "rke2", "2", "ubuntu-24.04")
        self.assertEqual(plan.status, "blocked")
        self.assertTrue(plan.blockers)

    def test_two_node_pacemaker_requires_stonith(self) -> None:
        plan = build_plan(self.catalog, "nextcloud-server", "pacemaker", "2", "rocky-9", allow_conditional=True)
        self.assertEqual(plan.status, "blocked")
        self.assertTrue(any("STONITH" in item for item in plan.blockers))

    def test_forward_os_is_explicitly_warned(self) -> None:
        plan = build_plan(self.catalog, "dspace", "docker", "1", "ubuntu-26.04")
        self.assertTrue(any("forward validation" in item for item in plan.warnings))

    def test_conditional_topology_requires_explicit_design_review(self) -> None:
        plan = build_plan(
            self.catalog,
            "paperless-ngx",
            "docker",
            "3",
            "ubuntu-24.04",
        )
        self.assertEqual(plan.status, "blocked")
        self.assertTrue(any("topology policy is conditional" in item for item in plan.blockers))

        approved = build_plan(
            self.catalog,
            "paperless-ngx",
            "docker",
            "3",
            "ubuntu-24.04",
            allow_conditional=True,
        )
        self.assertEqual(approved.status, "conditional")
        self.assertFalse(approved.blockers)

    def test_portable_support_never_reports_unqualified_ready(self) -> None:
        plan = build_plan(
            self.catalog,
            "paperless-ngx",
            "podman-quadlet",
            "1",
            "ubuntu-24.04",
        )
        self.assertEqual(plan.support_level, "portable")
        self.assertEqual(plan.status, "conditional")

    def test_ansible_is_an_orchestration_adapter(self) -> None:
        plan = build_plan(
            self.catalog,
            "paperless-ngx",
            "ansible",
            "3",
            "ubuntu-24.04",
            allow_conditional=True,
        )
        self.assertNotEqual(plan.status, "blocked")
        self.assertEqual(plan.support_level, "portable")
        self.assertEqual(plan.underlying_mode, "raw")
        self.assertTrue(any("not an HA runtime" in item for item in plan.warnings))
        self.assertTrue(any("run-ansible-operational.sh site.yml" in item for item in plan.commands))
        self.assertTrue(all("ansible-playbook" not in item for item in plan.commands))
        self.assertTrue(all("--ask-vault-pass" not in item for item in plan.commands))

    def test_ansible_uses_underlying_topology_policy(self) -> None:
        plan = build_plan(self.catalog, "paperless-ngx", "ansible", "2", "ubuntu-24.04", underlying_mode="rke2")
        self.assertEqual(plan.underlying_mode, "rke2")
        self.assertEqual(plan.topology_level, "not-recommended")
        self.assertEqual(plan.status, "blocked")
        self.assertTrue(any("RKE2 topology policy marks 2 nodes" in item for item in plan.blockers))

    def test_namespace_is_safe_for_generated_provider_commands(self) -> None:
        with self.assertRaises(ValueError):
            build_plan(self.catalog, "paperless-ngx", "rke2", "1", "ubuntu-24.04", namespace="archive; rm -rf /")

