from __future__ import annotations

import json
import sys
import tempfile
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.catalog import Catalog
from archiveweaver.checks import _command, check_url
from archiveweaver.repair import _resolve_ansible_bundle_path, apply_repair, build_repair_plan


class RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_default_repair_is_plan_only(self) -> None:
        plan = build_repair_plan(self.catalog, "paperless-ngx", "docker")
        result = apply_repair(plan, dry_run=True)
        self.assertEqual(result["status"], "planned")
        self.assertTrue(all(item["status"] == "planned" for item in result["results"]))
        self.assertNotIn("--remove-orphans", plan["actions"][1]["command"])

    def test_applied_repair_results_redact_command_output(self) -> None:
        plan = {
            "status": "ready",
            "actions": [{"name": "safe-probe", "command": [sys.executable, "-c", "print('sensitive-output')"]}],
        }
        result = apply_repair(plan)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["results"][0]["output_redacted"])
        self.assertNotIn("stdout", result["results"][0])
        self.assertNotIn("stderr", result["results"][0])

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
        redirect = urllib.error.HTTPError(
            "https://health.example.org/",
            302,
            "Found",
            {"Location": "https://other.example.org/"},
            None,
        )
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
        self.assertIn("verify,evidence", plan["actions"][-1]["command"])

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
            plan["actions"][0]["command"][2],
            str((ansible_root / "inventory" / "production" / "hosts.yml").resolve()),
        )
        self.assertEqual(
            plan["actions"][0]["command"][3],
            str((ansible_root / "repair.yml").resolve()),
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
