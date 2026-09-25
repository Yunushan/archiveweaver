from __future__ import annotations

import subprocess
import unittest
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

from archiveweaver.checks import (
    _NoRedirectHandler,
    _command,
    _open_health_request,
    _redacted_url,
    _runtime_commands,
    _url_scheme,
    check_commands,
    check_service,
    check_time_sync,
    check_url,
    detect_host,
)


class ExtendedCheckTests(unittest.TestCase):
    @patch("archiveweaver.checks.subprocess.run")
    def test_command_normalizes_output_and_process_errors(self, run: MagicMock) -> None:
        run.return_value = subprocess.CompletedProcess([], 4, " output \n", " error \n")
        self.assertEqual(_command("example"), (4, "output", "error"))
        run.side_effect = subprocess.TimeoutExpired("example", 1)
        code, stdout, stderr = _command("example", timeout=1)
        self.assertEqual((code, stdout), (127, ""))
        self.assertIn("timed out", stderr)

    @patch("archiveweaver.checks.socket.gethostname", return_value="archive-host")
    @patch("archiveweaver.checks._command", side_effect=[(0, "6.1", ""), (0, "x86_64", "")])
    @patch("archiveweaver.checks.Path")
    def test_detect_host_reads_os_release(
        self,
        path: MagicMock,
        command: MagicMock,
        _hostname: MagicMock,
    ) -> None:
        release = path.return_value
        release.exists.return_value = True
        release.read_text.return_value = (
            '# comment\nID="ubuntu"\nVERSION_ID="24.04"\n'
            'PRETTY_NAME="Ubuntu 24.04 LTS"\nMALFORMED\n'
        )
        host = detect_host()
        self.assertEqual(host["id"], "ubuntu")
        self.assertEqual(host["version_id"], "24.04")
        self.assertEqual(host["kernel"], "6.1")
        self.assertEqual(host["architecture"], "x86_64")
        self.assertEqual(host["hostname"], "archive-host")

        release.exists.return_value = False
        command.side_effect = [(127, "", ""), (127, "", "")]
        unknown = detect_host()
        self.assertEqual(unknown["id"], "unknown")
        self.assertEqual(unknown["kernel"], "unknown")

    @patch("archiveweaver.checks.shutil.which")
    def test_command_presence_reports_exact_missing_set(self, which: MagicMock) -> None:
        which.side_effect = lambda command: None if command == "missing" else f"/bin/{command}"
        failed = check_commands(["present", "missing"])
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["evidence"]["missing"], ["missing"])
        passed = check_commands(["present"])
        self.assertEqual(passed["status"], "pass")

    @patch("archiveweaver.checks.shutil.which", return_value=None)
    def test_service_requires_systemd_only_for_an_explicit_unit(self, _which: MagicMock) -> None:
        self.assertEqual(check_service("archive")["status"], "fail")
        self.assertEqual(check_service("archive", required=False)["status"], "skip")

    @patch("archiveweaver.checks._command")
    @patch("archiveweaver.checks.shutil.which", return_value="/bin/systemctl")
    def test_service_classifies_active_inactive_and_unknown(
        self,
        _which: MagicMock,
        command: MagicMock,
    ) -> None:
        command.return_value = (0, "active", "")
        self.assertEqual(check_service("archive")["status"], "pass")
        command.assert_called_with("systemctl", "is-active", "--", "archive")
        for state in ("inactive", "failed"):
            with self.subTest(state=state):
                command.return_value = (3, state, "journal unavailable")
                self.assertEqual(check_service("archive")["status"], "fail")
                self.assertEqual(check_service("archive", required=False)["status"], "skip")
        command.return_value = (3, "activating", "")
        self.assertEqual(check_service("archive")["status"], "warn")
        command.return_value = (4, "unknown", "not found")
        self.assertEqual(check_service("archive")["status"], "fail")
        self.assertEqual(check_service("archive", required=False)["status"], "skip")

    def test_service_rejects_option_and_control_syntax(self) -> None:
        for value in ("--root=/tmp", "archive\nforged", "archive\x1b[2J"):
            with self.subTest(value=value):
                result = check_service(value)
                self.assertEqual(result["status"], "fail")
                self.assertNotIn(value, str(result))

    @patch("archiveweaver.checks.shutil.which", return_value=None)
    def test_time_sync_skips_when_timedatectl_is_unavailable(self, _which: MagicMock) -> None:
        self.assertEqual(check_time_sync()["status"], "skip")

    @patch("archiveweaver.checks._command")
    @patch("archiveweaver.checks.shutil.which", return_value="/bin/timedatectl")
    def test_time_sync_classifies_query_failure_and_unknown_state(
        self,
        _which: MagicMock,
        command: MagicMock,
    ) -> None:
        command.return_value = (1, "", "dbus unavailable")
        failed_query = check_time_sync()
        self.assertEqual(failed_query["status"], "warn")
        self.assertEqual(failed_query["evidence"], "dbus unavailable")
        command.return_value = (0, "unknown", "")
        self.assertEqual(check_time_sync()["status"], "warn")

    def test_url_redaction_removes_credentials_query_and_fragment(self) -> None:
        self.assertEqual(
            _redacted_url("https://user:secret@example.org:8443/health?token=x#debug"),
            "https://example.org:8443/health",
        )
        self.assertEqual(_redacted_url(7), "<invalid-url>")
        self.assertEqual(_redacted_url("https://example.org/\nsecret"), "<redacted-url>")
        self.assertEqual(_url_scheme("https://["), "")

    @patch("archiveweaver.checks.urllib.request.build_opener")
    def test_health_request_uses_the_no_redirect_opener(self, build_opener: MagicMock) -> None:
        response = object()
        build_opener.return_value.open.return_value = response
        request = MagicMock()
        self.assertIs(_open_health_request(request, 9), response)
        build_opener.assert_called_once_with(_NoRedirectHandler)
        build_opener.return_value.open.assert_called_once_with(request, timeout=9)
        self.assertIsNone(
            _NoRedirectHandler().redirect_request(None, None, 302, "redirect", {}, "https://other.example")
        )

    def test_url_rejects_unsafe_or_non_http_endpoints(self) -> None:
        self.assertEqual(check_url("https://example.org/\nsecret")["status"], "fail")
        self.assertEqual(check_url("file:///etc/passwd")["status"], "fail")
        credentialed = check_url("https://user:secret@example.org/health")
        self.assertEqual(credentialed["status"], "fail")
        self.assertNotIn("secret", str(credentialed))
        self.assertEqual(check_url("https://example.org/health?token=x")["status"], "fail")
        self.assertEqual(check_url("https://example.org:bad/health")["status"], "fail")

    @patch("archiveweaver.checks._open_health_request")
    def test_url_classifies_success_warning_and_tls_downgrade(self, open_request: MagicMock) -> None:
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 204
        response.geturl.return_value = "https://example.org/health"
        open_request.return_value = response
        self.assertEqual(check_url("https://example.org/health")["status"], "pass")

        response.status = 304
        self.assertEqual(check_url("https://example.org/health")["status"], "warn")

        response.status = 200
        response.geturl.return_value = "http://example.org/health"
        self.assertEqual(check_url("https://example.org/health")["status"], "fail")

    @patch("archiveweaver.checks._open_health_request")
    def test_url_classifies_http_and_transport_errors(self, open_request: MagicMock) -> None:
        headers = Message()
        redirect = urllib.error.HTTPError(
            "https://example.org/login", 302, "redirect", headers, None
        )
        open_request.side_effect = redirect
        self.assertEqual(check_url("https://example.org/health")["status"], "fail")
        downgrade = urllib.error.HTTPError(
            "http://example.org/health", 307, "downgrade", headers, None
        )
        open_request.side_effect = downgrade
        self.assertEqual(check_url("https://example.org/health")["status"], "fail")
        unauthorized = urllib.error.HTTPError(
            "https://example.org/health", 401, "unauthorized", headers, None
        )
        open_request.side_effect = unauthorized
        self.assertEqual(check_url("https://example.org/health")["status"], "warn")
        unavailable = urllib.error.HTTPError(
            "https://example.org/health", 503, "unavailable", headers, None
        )
        open_request.side_effect = unavailable
        self.assertEqual(check_url("https://example.org/health")["status"], "fail")
        open_request.side_effect = urllib.error.URLError("certificate failure")
        result = check_url("https://example.org/health")
        self.assertEqual(result["status"], "fail")
        self.assertIn("TLS verification was not bypassed", result["detail"])

    def test_runtime_command_mapping_covers_every_runtime_family(self) -> None:
        self.assertEqual(_runtime_commands("raw"), ["systemctl"])
        self.assertEqual(_runtime_commands("docker-swarm"), ["docker"])
        self.assertEqual(_runtime_commands("podman-quadlet"), ["podman", "systemctl"])
        self.assertEqual(_runtime_commands("pacemaker"), ["pcs", "corosync", "pacemakerd"])
        self.assertEqual(_runtime_commands("ansible"), ["ansible-playbook"])
        self.assertEqual(_runtime_commands("rke2"), ["kubectl"])


if __name__ == "__main__":
    unittest.main()
