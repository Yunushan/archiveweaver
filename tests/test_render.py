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
        _, content = render(self.catalog, "paperless-ngx", "rke2", "3", "ubuntu-24.04", image="registry.example/paperless@sha256:abc")
        self.assertIn("podAntiAffinity", content)
        self.assertIn("ReadWriteMany", content)

    def test_raw_renderer_is_an_envelope(self) -> None:
        _, content = render(self.catalog, "dspace", "raw", "1", "ubuntu-24.04")
        self.assertIn("ExecStart=", content)
        self.assertIn("replace-with-upstream-command", content)
