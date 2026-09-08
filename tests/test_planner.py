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

