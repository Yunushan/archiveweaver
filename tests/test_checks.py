from __future__ import annotations

import unittest
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


if __name__ == "__main__":
    unittest.main()
