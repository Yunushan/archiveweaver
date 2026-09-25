from __future__ import annotations

import unittest
from pathlib import Path

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

    def test_docker_renderer_blocks_mutable_version_tag(self) -> None:
        with self.assertRaises(ValueError):
            render(
                self.catalog,
                "paperless-ngx",
                "docker",
                "1",
                "ubuntu-24.04",
                image="paperlessngx/paperless-ngx:2.14",
            )

    def test_non_production_override_allows_mutable_version_tag(self) -> None:
        _, content = render(
            self.catalog,
            "paperless-ngx",
            "docker",
            "1",
            "ubuntu-24.04",
            image="paperlessngx/paperless-ngx:2.14",
            allow_floating=True,
        )
        self.assertIn("paperlessngx/paperless-ngx:2.14", content)

    def test_kubernetes_renderer_contains_anti_affinity(self) -> None:
        _, content = render(self.catalog, "dspace", "rke2", "3", "ubuntu-24.04", image="registry.example/dspace@sha256:" + "a" * 64)
        self.assertIn("podAntiAffinity", content)
        self.assertIn("ReadWriteMany", content)

    def test_kubernetes_envelopes_deny_traffic_until_reviewed_rules_are_added(self) -> None:
        _, content = render(self.catalog, "dspace", "rke2", "3", "ubuntu-24.04", image="registry.example/dspace@sha256:" + "a" * 64)
        policy = content.split("kind: NetworkPolicy\n", 1)[1]
        self.assertIn("automountServiceAccountToken: false", content)
        self.assertIn("ingress: []", policy)
        self.assertIn("egress: []", policy)
        self.assertNotIn("- {}", policy)

        root = Path(__file__).resolve().parents[1]
        checked_in_policy = (root / "deploy/kubernetes/base/networkpolicy.yaml").read_text(encoding="utf-8")
        self.assertIn("ingress: []", checked_in_policy)
        self.assertIn("egress: []", checked_in_policy)
        self.assertNotIn("- {}", checked_in_policy)

    def test_multi_node_swarm_renderer_requires_external_storage(self) -> None:
        with self.assertRaisesRegex(ValueError, "shared or replicated"):
            render(
                self.catalog,
                "paperless-ngx",
                "docker-swarm",
                "3",
                "ubuntu-24.04",
                image="registry.example/paperless@sha256:" + "a" * 64,
            )

    def test_multi_node_swarm_renderer_uses_named_external_storage(self) -> None:
        plan, content = render(
            self.catalog,
            "paperless-ngx",
            "docker-swarm",
            "3",
            "ubuntu-24.04",
            image="registry.example/paperless@sha256:" + "a" * 64,
            external_storage=True,
        )
        self.assertTrue(plan["external_storage"])
        self.assertIn("external: true", content)
        self.assertIn("ARCHIVEWEAVER_DATA_VOLUME", content)
        self.assertNotIn("driver: local", content)
        self.assertNotIn("\n    ports:", content)
        self.assertNotIn("published:", content)
        self.assertNotIn("mode: ingress", content)

        root = Path(__file__).resolve().parents[1]
        checked_in_stack = (root / "deploy/docker-swarm/stack.yml").read_text(encoding="utf-8")
        self.assertNotIn("\n    ports:", checked_in_stack)
        self.assertNotIn("published:", checked_in_stack)
        self.assertNotIn("mode: ingress", checked_in_stack)

    def test_renderer_rejects_short_image_digest(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "rke2", "1", "ubuntu-24.04", image="registry.example/paperless@sha256:abc")

    def test_renderer_rejects_image_injection_characters(self) -> None:
        with self.assertRaises(ValueError):
            render(self.catalog, "paperless-ngx", "docker", "1", "ubuntu-24.04", image="repo/app:1\nmalicious")

    def test_renderer_rejects_whitespace_and_unsafe_image_boundaries(self) -> None:
        for image, message in (
            (" registry.example/app:1", "image reference is required"),
            ("registry.example/app/", "unsafe boundary"),
        ):
            with self.subTest(image=image):
                with self.assertRaisesRegex(ValueError, message):
                    render(
                        self.catalog,
                        "paperless-ngx",
                        "docker",
                        "1",
                        "ubuntu-24.04",
                        image=image,
                        allow_floating=True,
                    )

    def test_raw_renderer_is_an_envelope(self) -> None:
        _, content = render(self.catalog, "dspace", "raw", "1", "ubuntu-24.04")
        self.assertIn("ExecStart=", content)
        self.assertIn("replace-with-upstream-command", content)

    def test_ansible_renderer_defaults_to_plan_only(self) -> None:
        plan, content = render(
            self.catalog,
            "paperless-ngx",
            "ansible",
            "3",
            "ubuntu-24.04",
            allow_conditional=True,
        )
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
        self.assertIn('archiveweaver_ansible_core_version: "2.21.4"', content)
        self.assertIn('archiveweaver_ansible_lint_version: "26.8.0"', content)
        self.assertIn('archiveweaver_ansible_runner_version: "2.4.3"', content)
        self.assertIn('archiveweaver_execution_environment_digest: ""', content)
        self.assertIn('archiveweaver_runtime: "rke2"', content)

    def test_ansible_renderer_rejects_itself_as_underlying_provider(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be its own underlying runtime"):
            render(
                self.catalog,
                "paperless-ngx",
                "ansible",
                "3",
                "ubuntu-24.04",
                underlying_mode="ansible",
            )

    def test_single_node_swarm_uses_local_storage(self) -> None:
        plan, content = render(
            self.catalog,
            "paperless-ngx",
            "docker-swarm",
            "1",
            "ubuntu-24.04",
            image="registry.example/paperless@sha256:" + "a" * 64,
        )
        self.assertFalse(plan["external_storage"])
        self.assertIn("driver: local", content)
        self.assertNotIn("external: true", content)

    def test_kubernetes_node_count_does_not_scale_application_replicas(self) -> None:
        _, content = render(
            self.catalog,
            "dspace",
            "rke2",
            "3+",
            "ubuntu-24.04",
            image="registry.example/dspace@sha256:" + "a" * 64,
        )
        self.assertIn("replicas: 1", content)
        self.assertIn("type: Recreate", content)
        self.assertNotIn("RollingUpdate", content)

        root = Path(__file__).resolve().parents[1]
        base = (root / "deploy/kubernetes/base/deployment.yaml").read_text(encoding="utf-8")
        self.assertIn("type: Recreate", base)
        self.assertNotIn("maxSurge", base)
        for mode in ("rke2", "k3s", "k0s", "microk8s"):
            with self.subTest(mode=mode):
                patch = (root / f"deploy/kubernetes/overlays/{mode}/replicas-patch.yaml").read_text(encoding="utf-8")
                self.assertIn("replicas: 1", patch)
                self.assertNotIn("replicas: 3", patch)

    def test_paperless_kubernetes_render_requires_product_stack(self) -> None:
        for mode in ("rke2", "k3s", "k0s", "microk8s"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, "release-specific product stack.*PostgreSQL.*Redis-compatible"):
                    render(
                        self.catalog,
                        "paperless-ngx",
                        mode,
                        "3",
                        "ubuntu-24.04",
                        image="registry.example/paperless@sha256:" + "a" * 64,
                    )

    def test_pacemaker_requires_its_documented_resource_template(self) -> None:
        with self.assertRaisesRegex(ValueError, "documented Pacemaker resource template"):
            render(
                self.catalog,
                "nextcloud-server",
                "pacemaker",
                "1",
                "rocky-9",
                allow_conditional=True,
                image="registry.example/nextcloud@sha256:" + "a" * 64,
            )

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
