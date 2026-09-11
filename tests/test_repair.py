from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.error
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from archiveweaver.catalog import Catalog
from archiveweaver.checks import _command, check_url
from archiveweaver.repair import (
    _find_ansible_root,
    _resolve_ansible_bundle_path,
    _resolve_readiness_manifest_path,
    _safe_absolute_controller_path,
    _safe_relative_controller_path,
    _usable_ansible_root,
    apply_repair,
    build_repair_plan,
)


class RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_default_repair_is_plan_only(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "docker")
        result = apply_repair(plan, dry_run=True)
        self.assertEqual(result["status"], "planned")
        self.assertTrue(all(item["status"] == "planned" for item in result["results"]))
        self.assertNotIn("--remove-orphans", plan["actions"][1]["command"])

    def test_ansible_root_requires_a_complete_non_symlink_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "deploy" / "ansible"
            (root / "roles").mkdir(parents=True)
            (root / "ansible.cfg").write_text("[defaults]\n", encoding="utf-8")
            (root / "repair.yml").write_text("---\n", encoding="utf-8")
            self.assertTrue(_usable_ansible_root(root))

            real_config = root / "ansible.cfg.real"
            real_config.write_text("[defaults]\n", encoding="utf-8")
            (root / "ansible.cfg").unlink()
            try:
                (root / "ansible.cfg").symlink_to(real_config)
            except (OSError, NotImplementedError):
                return
            self.assertFalse(_usable_ansible_root(root))

    def test_controller_path_classification_is_fail_closed(self) -> None:
        self.assertTrue(_safe_relative_controller_path("inventory/production/hosts.yml"))
        self.assertFalse(_safe_relative_controller_path("../hosts.yml"))
        self.assertFalse(_safe_relative_controller_path(7))  # type: ignore[arg-type]
        absolute = str((Path.cwd() / "deploy" / "ansible" / "repair.yml").resolve())
        self.assertTrue(_safe_absolute_controller_path(absolute))
        self.assertFalse(_safe_absolute_controller_path("repair.yml"))
        self.assertFalse(_safe_absolute_controller_path(7))  # type: ignore[arg-type]

    def test_ansible_root_can_be_discovered_from_an_installed_data_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            installed_root = temporary / "site" / "share" / "archiveweaver" / "deploy" / "ansible"
            (installed_root / "roles").mkdir(parents=True)
            (installed_root / "ansible.cfg").write_text("[defaults]\n", encoding="utf-8")
            (installed_root / "repair.yml").write_text("---\n", encoding="utf-8")

            class InstalledDistribution:
                files = (
                    Path("share/archiveweaver/deploy/ansible/ansible.cfg"),
                )

                def locate_file(self, _path: object) -> Path:
                    return installed_root / "ansible.cfg"

            fake_module = temporary / "package" / "archiveweaver" / "repair.py"
            with (
                patch("archiveweaver.repair.Path.cwd", return_value=temporary),
                patch("archiveweaver.repair.__file__", str(fake_module)),
                patch(
                    "archiveweaver.repair.distribution",
                    return_value=InstalledDistribution(),
                ),
            ):
                self.assertEqual(_find_ansible_root(), installed_root.resolve())

    def test_ansible_bundle_path_rejects_unsafe_trust_boundaries(self) -> None:
        root = Path(__file__).resolve().parents[1] / "deploy" / "ansible"
        with patch(
            "archiveweaver.repair.has_symlink_component",
            side_effect=lambda path: Path(path) == root,
        ):
            with self.assertRaisesRegex(ValueError, "symlinked Ansible bundle"):
                _resolve_ansible_bundle_path("repair.yml", root, "--playbook")

        unresolved = root / "repair.yml"
        with patch(
            "archiveweaver.repair.has_symlink_component",
            side_effect=lambda path: Path(path) == unresolved,
        ):
            with self.assertRaisesRegex(ValueError, "must not resolve through a symlink"):
                _resolve_ansible_bundle_path("repair.yml", root, "--playbook")

    def test_readiness_manifest_requires_the_ansible_directory_after_resolution(self) -> None:
        root = Path(__file__).resolve().parents[1] / "deploy" / "ansible"
        outside = root.parent / "outside.json"
        with patch(
            "archiveweaver.repair._resolve_ansible_bundle_path",
            return_value=outside,
        ):
            with self.assertRaisesRegex(ValueError, "Ansible playbook directory"):
                _resolve_readiness_manifest_path("outside.json", root)

    def test_applied_repair_results_redact_command_output(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "raw")
        completed = type("Completed", (), {"returncode": 0})()
        with patch(
            "archiveweaver.repair.subprocess.run", return_value=completed
        ) as run:
            result = apply_repair(plan)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["results"][0]["output_redacted"])
        self.assertNotIn("stdout", result["results"][0])
        self.assertNotIn("stderr", result["results"][0])
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("capture_output", run.call_args.kwargs)

    def test_apply_repair_stops_on_command_failure_and_preserves_environment(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "ansible")
        completed = type("Completed", (), {"returncode": 9})()
        with patch("archiveweaver.repair.subprocess.run", return_value=completed) as run:
            result = apply_repair(plan)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["returncode"], 9)
        self.assertEqual(
            run.call_args.kwargs["env"]["ANSIBLE_CONFIG"],
            str(Path.cwd() / "deploy" / "ansible" / "ansible.cfg"),
        )

    def test_apply_repair_rejects_forged_and_modified_ready_plans(self) -> None:
        forged = {
            "status": "ready",
            "actions": [
                {"name": "forged", "command": [sys.executable, "-c", "pass"]}
            ],
        }
        with patch("archiveweaver.repair.subprocess.run") as run:
            rejected = apply_repair(forged)
        self.assertEqual(rejected["status"], "blocked")
        self.assertIn("trusted plan builder", rejected["blockers"][0])
        run.assert_not_called()

        modified = build_repair_plan(self.catalog, "paperless-ngx", "raw")
        modified["actions"][0]["command"] = [sys.executable, "-c", "pass"]
        with patch("archiveweaver.repair.subprocess.run") as run:
            rejected = apply_repair(modified)
        self.assertEqual(rejected["status"], "blocked")
        self.assertIn("changed after it was reviewed", rejected["blockers"][0])
        run.assert_not_called()

    def test_apply_repair_handles_blocked_and_process_errors(self) -> None:
        blocked = apply_repair({"status": "blocked"})
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blockers"], ["repair plan is not ready"])

        plan = build_repair_plan(self.catalog, "paperless-ngx", "raw")
        with patch("archiveweaver.repair.subprocess.run", side_effect=OSError("missing")):
            failed = apply_repair(plan)
        self.assertEqual(failed["status"], "fail")
        self.assertTrue(failed["results"][0]["output_redacted"])

    def test_pacemaker_is_gated(self) -> None:
        plan = build_repair_plan(self.catalog, "nextcloud-server", "pacemaker")
        self.assertEqual(plan["status"], "blocked")

    def test_url_check_rejects_non_http_schemes(self) -> None:
        result = check_url("file:///etc/passwd")
        self.assertEqual(result["status"], "fail")

    def test_url_check_reports_malformed_hosts_without_crashing(self) -> None:
        result = check_url("https://[")
        self.assertEqual(result["status"], "fail")
        self.assertIn("could not be parsed", result["detail"])

    def test_command_permission_errors_are_reported_without_crashing(self) -> None:
        with patch("archiveweaver.checks.subprocess.run", side_effect=PermissionError("denied")):
            code, stdout, stderr = _command("blocked-command")
        self.assertEqual(code, 127)
        self.assertEqual(stdout, "")
        self.assertIn("denied", stderr)

    def test_health_check_rejects_credentials_and_query_data(self) -> None:
        credentials = check_url("https://user:password@health.example.org/")
        query = check_url("https://health.example.org/?token=secret")
        self.assertEqual(credentials["status"], "fail")
        self.assertEqual(query["status"], "fail")
        self.assertNotIn("password", json.dumps(credentials))
        self.assertNotIn("secret", json.dumps(query))

    def test_health_check_rejects_report_unsafe_url_characters(self) -> None:
        result = check_url("https://health.example.org/health\\ncheck")
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("\\ncheck", json.dumps(result))

    def test_https_health_check_rejects_downgrade_redirect(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def geturl(self):
                return "http://health.example.org/"

        with patch("archiveweaver.checks._open_health_request", return_value=Response()):
            result = check_url("https://health.example.org/")
        self.assertEqual(result["status"], "fail")
        self.assertIn("non-HTTPS", result["detail"])

    def test_health_check_rejects_redirect_responses(self) -> None:
        headers = Message()
        headers["Location"] = "https://other.example.org/"
        redirect = urllib.error.HTTPError(
            "https://health.example.org/",
            302,
            "Found",
            headers,
            None,
        )
        with patch("archiveweaver.checks._open_health_request", side_effect=redirect):
            result = check_url("https://health.example.org/")
        redirect.close()
        self.assertEqual(result["status"], "fail")
        self.assertIn("do not follow redirects", result["detail"])

    def test_health_check_handles_unreadable_http_error_urls(self) -> None:
        class FragileHTTPError(urllib.error.HTTPError):
            def __init__(self):
                self.code = 302

            @property
            def url(self):
                raise KeyError("url is unavailable")

        redirect = FragileHTTPError()
        with patch("archiveweaver.checks._open_health_request", side_effect=redirect):
            result = check_url("https://health.example.org/")
        self.assertEqual(result["status"], "fail")
        self.assertIn("do not follow redirects", result["detail"])

    def test_ansible_repair_is_plan_only_by_default(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "ansible")
        result = apply_repair(plan, dry_run=True)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(plan["underlying_mode"], "raw")
        self.assertEqual([item["name"] for item in plan["actions"]], [
            "validate-playbook", "plan-repair", "apply-repair", "verify-repair",
        ])

    def test_ansible_repair_binds_underlying_provider(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "ansible", underlying_mode="rke2")
        self.assertEqual(plan["underlying_mode"], "rke2")
        self.assertTrue(any("archiveweaver_runtime=rke2" in arg for action in plan["actions"] for arg in action["command"]))
        self.assertTrue(any("archiveweaver_readiness_manifest_path=" in arg for action in plan["actions"] for arg in action["command"]))
        self.assertTrue(all("archiveweaver_readiness_manifest_path=.." not in arg for action in plan["actions"] for arg in action["command"]))
        self.assertTrue(any("archiveweaver_readiness_manifest_path=" in arg and "release-manifest.json" in arg for action in plan["actions"] for arg in action["command"]))
        self.assertTrue(all("ANSIBLE_CONFIG" in action["environment"] for action in plan["actions"]))
        self.assertTrue(all("ANSIBLE_ROLES_PATH" in action["environment"] for action in plan["actions"]))
        self.assertTrue(all("run-ansible-operational.sh" in action["command"][1] for action in plan["actions"]))
        self.assertTrue(all("--tags" not in action["command"] for action in plan["actions"]))
        self.assertNotIn("verify,evidence", plan["actions"][-1]["command"])

        bound = build_repair_plan(
            self.catalog,
            "paperless-ngx",
            "ansible",
            underlying_mode="rke2",
            operator="release-operator",
            fixture_set="paperless-fixtures-v1",
            execution_environment_digest="sha256:" + "a" * 64,
        )
        self.assertTrue(any("archiveweaver_operator=release-operator" in arg for action in bound["actions"] for arg in action["command"]))
        self.assertTrue(any("archiveweaver_fixture_set=paperless-fixtures-v1" in arg for action in bound["actions"] for arg in action["command"]))
        self.assertTrue(any("archiveweaver_execution_environment_digest=sha256:" + "a" * 64 in arg for action in bound["actions"] for arg in action["command"]))

    def test_ansible_repair_defaults_work_from_ansible_directory(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        ansible_root = repository_root / "deploy" / "ansible"
        with patch("archiveweaver.repair.Path.cwd", return_value=ansible_root):
            plan = build_repair_plan(self.catalog, "paperless-ngx", "ansible")

        self.assertEqual(
            plan["actions"][0]["command"][4],
            str((ansible_root / "inventory" / "production" / "hosts.yml").resolve()),
        )
        self.assertEqual(
            plan["actions"][0]["command"][:3],
            [
                "bash",
                str((repository_root / "scripts" / "run-ansible-operational.sh").resolve()),
                "repair.yml",
            ],
        )
        self.assertTrue(any(
            "archiveweaver_readiness_manifest_path="
            + str((ansible_root / "release-manifest.json").resolve()) in arg
            for action in plan["actions"]
            for arg in action["command"]
        ))

    def test_ansible_repair_rejects_invalid_execution_environment_digest(self) -> None:
        with self.assertRaises(ValueError):
            build_repair_plan(
                self.catalog,
                "paperless-ngx",
                "ansible",
                execution_environment_digest="not-a-digest",
            )

    def test_ansible_pacemaker_repair_requires_fencing_permission(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "ansible", underlying_mode="pacemaker")
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["actions"], [])

    def test_repair_plans_cover_each_runtime_family(self) -> None:
        cases = (
            ("raw", {"service": "paperless"}, "restart-service"),
            ("podman-quadlet", {"unit": "paperless.service"}, "restart-quadlet"),
            (
                "pacemaker",
                {"resource": "paperless", "allow_fencing_actions": True},
                "resource-cleanup",
            ),
            ("docker-swarm", {"compose_file": "stack.yml"}, "redeploy-stack"),
            (
                "rke2",
                {"namespace": "archive", "deployment": "paperless"},
                "rollout-restart",
            ),
        )
        for mode, options, expected_action in cases:
            with self.subTest(mode=mode):
                plan = build_repair_plan(
                    self.catalog,
                    "paperless-ngx",
                    mode,
                    **options,
                )
                self.assertEqual(plan["status"], "ready")
                self.assertIn(expected_action, [item["name"] for item in plan["actions"]])

    def test_ansible_only_arguments_are_rejected_for_other_modes(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be its own"):
            build_repair_plan(
                self.catalog,
                "paperless-ngx",
                "ansible",
                underlying_mode="ansible",
            )
        with self.assertRaisesRegex(ValueError, "only valid when --mode ansible"):
            build_repair_plan(
                self.catalog,
                "paperless-ngx",
                "docker",
                underlying_mode="raw",
            )
        with self.assertRaisesRegex(ValueError, "only valid when --mode ansible"):
            build_repair_plan(
                self.catalog,
                "paperless-ngx",
                "docker",
                readiness_manifest="release-manifest.json",
            )

    def test_ansible_repair_requires_approved_playbook_and_runner(self) -> None:
        with self.assertRaisesRegex(ValueError, "approved Ansible repair.yml"):
            build_repair_plan(
                self.catalog,
                "paperless-ngx",
                "ansible",
                playbook="deploy/ansible/site.yml",
            )

        runner_name = "run-ansible-operational.sh"
        with patch(
            "archiveweaver.repair.has_symlink_component",
            side_effect=lambda path: Path(path).name == runner_name,
        ):
            with self.assertRaisesRegex(ValueError, "runner is missing or unsafe"):
                build_repair_plan(self.catalog, "paperless-ngx", "ansible")

    def test_ansible_repair_rejects_unsafe_readiness_path(self) -> None:
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "ansible", readiness_manifest="../release-manifest.json")

    def test_ansible_repair_rejects_manifest_outside_playbook_bundle(self) -> None:
        with self.assertRaises(ValueError):
            outside = Path(Path.cwd().anchor) / "outside" / "release-manifest.json"
            build_repair_plan(self.catalog, "paperless-ngx", "ansible", readiness_manifest=str(outside))

    def test_ansible_repair_rejects_playbook_or_inventory_outside_bundle(self) -> None:
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "ansible", playbook="../repair.yml")
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "ansible", inventory="../hosts.yml")

    def test_ansible_repair_rejects_symlinked_controller_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ansible"
            root.mkdir()
            target = root / "reviewed.yml"
            target.write_text("---\n", encoding="utf-8")
            link = root / "link.yml"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"file symlinks are unavailable: {exc}")
            with self.assertRaises(ValueError):
                _resolve_ansible_bundle_path(str(link), root, "--playbook")

    def test_ansible_repair_rejects_secret_like_identity_values(self) -> None:
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "ansible", operator="bad operator")

    def test_repair_rejects_unsafe_target_identifiers(self) -> None:
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "raw", service="--user")
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "docker", compose_file="--env-file")
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "podman-quadlet", unit="--all")
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "nextcloud-server", "pacemaker", resource="resource;cleanup", allow_fencing_actions=True)
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "rke2", namespace="archive;weaver")
        with self.assertRaises(ValueError):
            build_repair_plan(self.catalog, "paperless-ngx", "rke2", deployment="deployment/name")
