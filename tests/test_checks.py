from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.catalog import Catalog
from archiveweaver.checks import check_time_sync, run_checks


HOST = {
    "id": "test",
    "version_id": "1",
    "pretty_name": "Test OS",
    "kernel": "test",
    "architecture": "x86_64",
    "hostname": "test-host",
}


class CheckTests(unittest.TestCase):
    @patch("archiveweaver.checks._command", return_value=(0, "yes", ""))
    @patch("archiveweaver.checks.shutil.which", return_value="/usr/bin/timedatectl")
    def test_time_sync_passes_only_for_a_synchronized_clock(
        self,
        _which: object,
        _command: object,
    ) -> None:
        self.assertEqual(check_time_sync()["status"], "pass")

    @patch("archiveweaver.checks._command", return_value=(0, "no", ""))
    @patch("archiveweaver.checks.shutil.which", return_value="/usr/bin/timedatectl")
    def test_time_sync_fails_for_an_unsynchronized_clock(
        self,
        _which: object,
        _command: object,
    ) -> None:
        self.assertEqual(check_time_sync()["status"], "fail")

    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_summary_warns_when_no_meaningful_probe_passes(
        self,
        _host: object,
        time_sync: object,
        service: object,
    ) -> None:
        time_sync.return_value = {
            "name": "host-time",
            "status": "skip",
            "detail": "unavailable",
        }
        service.return_value = {
            "name": "service:test",
            "status": "skip",
            "detail": "unavailable",
        }
        report = run_checks(Catalog(), "paperless-ngx")
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["meaningful_passes"], 0)
        self.assertGreater(report["summary"]["skipped"], 0)
        self.assertIn("product-health", {item["name"] for item in report["checks"]})

    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_existing_paths_and_config_cannot_report_product_health(
        self,
        _host: object,
        time_sync: object,
        service: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        service.return_value = {"name": "service:test", "status": "skip", "detail": "unavailable"}
        report = run_checks(
            Catalog(),
            "paperless-ngx",
            paths=["."],
            config=str(Path(__file__)),
        )
        by_name = {item["name"]: item for item in report["checks"]}
        self.assertEqual(by_name["path:."]["status"], "pass")
        self.assertEqual(by_name["configuration"]["status"], "pass")
        self.assertEqual(by_name["product-health"]["status"], "warn")
        self.assertEqual(report["summary"]["meaningful_passes"], 0)
        self.assertEqual(report["summary"]["status"], "warn")

    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_discovered_inactive_aliases_do_not_hide_an_active_service(
        self,
        _host: object,
        time_sync: object,
        service: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        service.side_effect = lambda name, *, required: {
            "name": f"service:{name}",
            "status": "pass" if name == "paperless" else "skip",
            "detail": "active" if name == "paperless" else "inactive",
        }
        report = run_checks(Catalog(), "paperless-ngx")
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["meaningful_passes"], 1)
        self.assertTrue(all(not call.kwargs["required"] for call in service.call_args_list))

    @patch("archiveweaver.checks._command")
    @patch("archiveweaver.checks.shutil.which", return_value="/bin/systemctl")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_explicit_inactive_or_failed_service_fails_the_run(
        self,
        _host: object,
        time_sync: object,
        _which: object,
        command: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        for state in ("inactive", "failed"):
            with self.subTest(state=state):
                command.return_value = (3, state, "")
                report = run_checks(Catalog(), "paperless-ngx", service="paperless")
                by_name = {item["name"]: item for item in report["checks"]}
                self.assertEqual(by_name["service:paperless"]["status"], "fail")
                self.assertEqual(report["summary"]["status"], "fail")

    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_explicit_empty_probe_values_are_not_treated_as_missing(
        self,
        _host: object,
        time_sync: object,
        service: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        service.return_value = {"name": "service:<invalid>", "status": "fail", "detail": "invalid"}
        report = run_checks(Catalog(), "paperless-ngx", service="", url="")
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(next(item for item in report["checks"] if item["name"] == "http")["status"], "fail")
        service.assert_called_once_with("", required=True)

    @patch("archiveweaver.checks.check_url")
    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_summary_passes_with_a_successful_meaningful_probe(
        self,
        _host: object,
        time_sync: object,
        service: object,
        url: object,
    ) -> None:
        time_sync.return_value = {
            "name": "host-time",
            "status": "pass",
            "detail": "synchronized",
        }
        service.return_value = {
            "name": "service:test",
            "status": "skip",
            "detail": "unavailable",
        }
        url.return_value = {
            "name": "http",
            "status": "pass",
            "detail": "HTTP 200",
        }
        report = run_checks(
            Catalog(),
            "paperless-ngx",
            url="https://health.example.org/",
        )
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["meaningful_passes"], 1)

    @patch("archiveweaver.checks.check_commands")
    @patch("archiveweaver.checks.check_service")
    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_runtime_paths_and_configuration_are_reported(
        self,
        _host: object,
        time_sync: object,
        service: object,
        commands: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        service.return_value = {"name": "service:test", "status": "pass", "detail": "active"}
        commands.return_value = {"name": "runtime:docker", "status": "pass", "detail": "ok"}
        existing = Path(__file__).resolve()
        missing = existing.with_name("__archiveweaver_missing_check_fixture__.conf")
        self.assertFalse(missing.exists())
        report = run_checks(
            Catalog(),
            "paperless-ngx",
            mode="docker",
            paths=[str(existing), str(missing)],
            config=str(existing),
        )

        by_name = {item["name"]: item for item in report["checks"]}
        self.assertEqual(by_name["runtime:docker"]["status"], "pass")
        self.assertEqual(by_name["service:test"]["status"], "pass")
        self.assertEqual(by_name[f"path:{existing}"]["status"], "pass")
        self.assertEqual(by_name[f"path:{missing}"]["status"], "fail")
        self.assertEqual(by_name["configuration"]["status"], "pass")
        self.assertEqual(report["summary"]["status"], "fail")

    @patch("archiveweaver.checks.check_time_sync")
    @patch("archiveweaver.checks.detect_host", return_value=HOST)
    def test_empty_service_aliases_and_missing_configuration_are_explicit(
        self,
        _host: object,
        time_sync: object,
    ) -> None:
        time_sync.return_value = {"name": "host-time", "status": "pass", "detail": "ok"}
        catalog = Catalog()
        catalog.solutions["paperless-ngx"]["health"]["service_aliases"] = []
        report = run_checks(
            catalog,
            "paperless-ngx",
            config="missing-production-configuration.yml",
        )
        names = {item["name"] for item in report["checks"]}
        self.assertNotIn("services", names)
        configuration = next(item for item in report["checks"] if item["name"] == "configuration")
        self.assertEqual(configuration["status"], "fail")


if __name__ == "__main__":
    unittest.main()
