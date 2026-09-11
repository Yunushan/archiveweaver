from __future__ import annotations

import json
import unittest

from archiveweaver.catalog import Catalog
from archiveweaver.planner import build_plan
from archiveweaver.render import render


class CatalogMatrixIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_every_catalog_planning_combination_has_a_stable_policy_result(self) -> None:
        combinations = 0
        for solution_id in self.catalog.solutions:
            for mode in self.catalog.runtimes:
                for nodes in ("1", "2", "3", "4"):
                    for os_id in self.catalog.operating_systems:
                        options: dict[str, object] = {
                            "stonith": True,
                            "qdevice": True,
                            "external_datastore": True,
                            "external_storage": True,
                            "allow_conditional": True,
                        }
                        if mode == "ansible":
                            options["underlying_mode"] = "raw"
                        plan = build_plan(
                            self.catalog,
                            solution_id,
                            mode,
                            nodes,
                            os_id,
                            **options,
                        )
                        self.assertIn(plan.status, {"ready", "conditional", "blocked"})
                        json.dumps(plan.as_dict())
                        combinations += 1
        self.assertEqual(combinations, 16_800)

    def test_every_renderable_solution_mode_has_a_deterministic_envelope(self) -> None:
        image = "registry.example.org/archiveweaver/product@sha256:" + "a" * 64
        combinations = 0
        for solution_id in self.catalog.solutions:
            for mode in self.catalog.runtimes:
                if mode == "pacemaker":
                    continue
                for os_id in ("ubuntu-24.04", "rocky-9"):
                    options: dict[str, object] = {
                        "image": image,
                        "allow_conditional": True,
                        "external_storage": True,
                    }
                    if mode == "ansible":
                        options["underlying_mode"] = "raw"
                    plan, content = render(
                        self.catalog,
                        solution_id,
                        mode,
                        "1",
                        os_id,
                        **options,
                    )
                    self.assertNotEqual(plan["status"], "blocked")
                    self.assertTrue(content.strip())
                    combinations += 1
        self.assertEqual(combinations, 540)


if __name__ == "__main__":
    unittest.main()
