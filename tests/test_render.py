from __future__ import annotations

import unittest

from archiveweaver.catalog import Catalog
from archiveweaver.render import render


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_docker_renderer_blocks_floating_image(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "docker", "1", "ubuntu-24.04", image="paperlessngx/paperless-ngx:latest")

    def test_docker_renderer_blocks_untagged_image(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "docker", "1", "ubuntu-24.04", image="paperlessngx/paperless-ngx")

    def test_kubernetes_renderer_contains_anti_affinity(self) -> None:
        _, content = render(self.catalog, "paperless-ngx", "rke2", "3", "ubuntu-24.04", image="registry.example/paperless@sha256:" + "a" * 64)
        self.assertIn("podAntiAffinity", content)
        self.assertIn("ReadWriteMany", content)

    def test_renderer_rejects_short_image_digest(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "rke2", "1", "ubuntu-24.04", image="registry.example/paperless@sha256:abc")

    def test_renderer_rejects_image_injection_characters(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "docker", "1", "ubuntu-24.04", image="repo/app:1\nmalicious")

    def test_raw_renderer_is_an_envelope(self) -> None:
        _, content = render(self.catalog, "dspace", "raw", "1", "ubuntu-24.04")
        self.assertIn("ExecStart=", content)
        self.assertIn("replace-with-upstream-command", content)

    def test_ansible_renderer_defaults_to_plan_only(self) -> None:
        plan, content = render(self.catalog, "paperless-ngx", "ansible", "3", "ubuntu-24.04")
        self.assertEqual(plan["mode"], "ansible")
        self.assertIn("archiveweaver_apply: false", content)
        self.assertIn("archiveweaver_preflight", content)
        self.assertIn("archiveweaver_provider", content)
        self.assertIn("archiveweaver_evidence", content)
        self.assertIn("archiveweaver_controller_preflight", content)
        self.assertIn("archiveweaver_controller_target_group: archiveweaver_nodes", content)
        self.assertIn("scripts/run-ansible-operational.sh", content)
        self.assertIn("review artifact", content)
        self.assertLess(content.index("hosts: localhost"), content.index("hosts: archiveweaver_nodes"))
        self.assertLess(content.index("hosts: archiveweaver_nodes"), content.rindex("hosts: localhost"))
        self.assertIn('archiveweaver_operator: ""', content)
        self.assertIn('archiveweaver_evidence_environment: "production"', content)
        self.assertIn("archiveweaver_run_verification: false", content)
        self.assertIn("archiveweaver_evidence_completion_fact: archiveweaver_verify_completed", content)
        self.assertIn("archiveweaver_evidence_completion_hosts:", content)

    def test_ansible_renderer_selects_underlying_provider(self) -> None:
        plan, content = render(
            self.catalog,
            "paperless-ngx",
            "ansible",
            "3",
            "ubuntu-24.04",
            underlying_mode="rke2",
        )
        self.assertEqual(plan["underlying_mode"], "rke2")
        self.assertIn('archiveweaver_ansible_core_version: "2.21.0"', content)
        self.assertIn('archiveweaver_execution_environment_digest: ""', content)
        self.assertIn('archiveweaver_runtime: "rke2"', content)

    def test_renderer_rejects_underlying_provider_for_non_ansible_mode(self) -> None:
        with self.assertRaises(ValueError):
            render(
                self.catalog,
                "paperless-ngx",
                "docker",
                "1",
                "ubuntu-24.04",
                underlying_mode="rke2",
            )
