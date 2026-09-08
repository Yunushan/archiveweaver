from __future__ import annotations

import unittest

from archiveweaver.catalog import Catalog
from archiveweaver.checks import check_url
from archiveweaver.repair import apply_repair, build_repair_plan


class RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_default_repair_is_plan_only(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "docker")
        result = apply_repair(plan, dry_run=True)
        self.assertEqual(result["status"], "planned")
        self.assertTrue(all(item["status"] == "planned" for item in result["results"]))

    def test_pacemaker_is_gated(self) -> None:
        plan = build_repair_plan(self.catalog, "nextcloud-server", "pacemaker")
        self.assertEqual(plan["status"], "blocked")

    def test_url_check_rejects_non_http_schemes(self) -> None:
        result = check_url("file:///etc/passwd")
        self.assertEqual(result["status"], "fail")
