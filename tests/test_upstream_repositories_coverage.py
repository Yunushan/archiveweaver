from __future__ import annotations

import importlib.util
import io
import json
import runpy
import sys
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate-upstream-repositories.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_upstream_repositories_coverage", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            payload, self.payload = self.payload, b""
            return payload
        payload, self.payload = self.payload[:size], self.payload[size:]
        return payload


class _TextResponse:
    def __enter__(self) -> _TextResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> str:
        return "{}"


class _ValidOpener:
    def open(self, request: urllib.request.Request, timeout: int = 20) -> _Response:
        slug = request.full_url.rsplit("/repos/", 1)[1]
        payload = json.dumps(
            {
                "full_name": slug,
                "disabled": False,
                "archived": False,
                "pushed_at": None,
            }
        ).encode()
        return _Response(payload)


class UpstreamRepositoryCoverageTests(unittest.TestCase):
    def test_open_github_request_builds_opener_without_redirects(self) -> None:
        opener = Mock()
        opener.open.return_value = "opened"
        request = urllib.request.Request("https://api.github.com/repos/example/repo")
        with patch.object(
            urllib.request, "build_opener", return_value=opener
        ) as build_opener:
            result = module._open_github_request(request, timeout=7)
        self.assertEqual(result, "opened")
        build_opener.assert_called_once_with(module._NoRedirectHandler)
        opener.open.assert_called_once_with(request, timeout=7)

    def test_github_slug_rejects_invalid_owner_and_repository_tokens(self) -> None:
        for rejected in (
            "https://github.com/-org/repo",
            "https://github.com/org-/repo",
            "https://github.com/org/..",
            "https://github.com/org/.git",
        ):
            with self.subTest(url=rejected):
                self.assertIsNone(module.github_slug(rejected))

    def test_json_nesting_scanner_handles_escaped_strings(self) -> None:
        module._reject_excessive_json_nesting('"escaped \\" quote"', "example/repo")
        module._reject_excessive_json_nesting('"double \\\\ slash"', "example/repo")

    def test_json_parsing_hooks_accept_and_reject_values(self) -> None:
        self.assertEqual(module._reject_oversized_json_integer("-12"), -12)
        self.assertEqual(module._reject_oversized_json_integer("9" * 4300), int("9" * 4300))
        with self.assertRaisesRegex(ValueError, "oversized JSON number"):
            module._reject_oversized_json_integer("9" * 4301)
        self.assertEqual(module._reject_oversized_or_non_finite_json_float("1.5"), 1.5)
        with self.assertRaisesRegex(ValueError, "oversized JSON number"):
            module._reject_oversized_or_non_finite_json_float("1" * 4301)
        with self.assertRaisesRegex(ValueError, "non-finite JSON number"):
            module._reject_oversized_or_non_finite_json_float("1e9999")
        with self.assertRaisesRegex(ValueError, "non-standard JSON numeric value"):
            module._reject_non_finite_json_constant("NaN")
        self.assertEqual(
            module._reject_duplicate_json_keys([("a", 1), ("b", 2)]),
            {"a": 1, "b": 2},
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            module._reject_duplicate_json_keys([("a", 1), ("a", 2)])

    def test_load_api_json_rejects_non_byte_and_invalid_utf8_responses(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-byte response"):
            module._load_api_json(_TextResponse(), "example/repo")
        with self.assertRaisesRegex(ValueError, "malformed JSON"):
            module._load_api_json(_Response(b"\xff"), "example/repo")

    def test_github_fetcher_sends_token_and_rejects_non_object_payload(self) -> None:
        captured: dict[str, object] = {}

        def fake_open(request: urllib.request.Request, timeout: int) -> _Response:
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response(b'{"full_name": "example/repo"}')

        with patch.object(module, "_open_github_request", fake_open):
            result = module.github_fetcher("secret-token")("example/repo")
        self.assertEqual(result["full_name"], "example/repo")
        self.assertEqual(captured["timeout"], 20)
        request = captured["request"]
        assert isinstance(request, urllib.request.Request)
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(
            request.get_header("X-github-api-version"), "2022-11-28"
        )
        with patch.object(
            module, "_open_github_request", Mock(return_value=_Response(b"[]"))
        ), self.assertRaisesRegex(ValueError, "non-object"):
            module.github_fetcher(None)("example/repo")

    def test_github_fetcher_retries_transient_failures(self) -> None:
        fetch = module.github_fetcher(None)
        http_errors = [
            urllib.error.HTTPError("https://api.github.com", 503, "down", {}, None),
            urllib.error.HTTPError("https://api.github.com", 502, "down", {}, None),
            urllib.error.HTTPError("https://api.github.com", 500, "down", {}, None),
        ]
        with patch.object(
            module, "_open_github_request", Mock(side_effect=http_errors)
        ), patch.object(module.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                fetch("example/repo")
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

        with patch.object(
            module, "_open_github_request", Mock(side_effect=urllib.error.URLError("down"))
        ), patch.object(module.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.URLError):
                fetch("example/repo")
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_github_fetcher_raises_when_retry_loop_is_not_entered(self) -> None:
        with patch.dict(module.__dict__, {"range": lambda _stop: []}):
            with self.assertRaisesRegex(RuntimeError, "GitHub request failed"):
                module.github_fetcher(None)("example/repo")

    def test_audit_handles_absent_and_malformed_urls(self) -> None:
        solutions = [
            {"id": "absent", "upstream_repo": None, "source_repo": None},
            {
                "id": "malformed",
                "upstream_repo": "https://[::1/org/repo",
                "source_repo": "https://[::1/org/repo",
            },
        ]
        errors, warnings, checked, non_github = module.audit(
            solutions, Mock(side_effect=AssertionError("no fetch expected"))
        )
        self.assertEqual((errors, warnings, checked, non_github), ([], [], 0, 1))

    def test_audit_warns_for_stale_and_recent_push_timestamps(self) -> None:
        solutions = [
            {
                "id": "stale",
                "upstream_repo": "https://github.com/example/stale",
                "source_repo": None,
                "notes": [],
            },
            {
                "id": "fresh",
                "upstream_repo": "https://github.com/example/fresh",
                "source_repo": None,
                "notes": [],
            },
        ]
        old = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
        fresh = datetime.now(timezone.utc).isoformat()

        def fetch(slug: str) -> dict[str, object]:
            return {
                "full_name": slug,
                "disabled": False,
                "archived": False,
                "pushed_at": old if slug.endswith("stale") else fresh,
            }

        errors, warnings, checked, non_github = module.audit(solutions, fetch)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("has had no push for", warnings[0])
        self.assertEqual((checked, non_github), (2, 0))

    def test_main_reports_catalog_load_failures(self) -> None:
        for read_text in (
            Mock(side_effect=OSError("denied")),
            Mock(side_effect=UnicodeError("bad encoding")),
            Mock(return_value="{"),
        ):
            stderr = io.StringIO()
            with patch.object(module, "CATALOG", Mock(read_text=read_text)):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    self.assertEqual(module.main(), 2)
            self.assertIn("failed to load catalog", stderr.getvalue())

    def test_main_rejects_non_list_catalog(self) -> None:
        for payload in ('{"a": 1}', "[1]"):
            stderr = io.StringIO()
            with patch.object(
                module, "CATALOG", Mock(read_text=Mock(return_value=payload))
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(module.main(), 2)
            self.assertIn("requires a list of solution objects", stderr.getvalue())

    def test_main_reports_warnings_and_errors_with_token(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        audit_mock = Mock(return_value=(["boom"], ["care"], 3, 2))
        fetcher = Mock(return_value=Mock())
        with patch.object(
            module, "CATALOG", Mock(read_text=Mock(return_value="[]"))
        ), patch.object(module, "github_fetcher", fetcher), patch.object(
            module, "audit", audit_mock
        ), patch.dict(module.os.environ, {"GITHUB_TOKEN": "tok"}):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = module.main()
        self.assertEqual(result, 1)
        fetcher.assert_called_once_with("tok")
        self.assertIn("warning: care", stderr.getvalue())
        self.assertIn("error: boom", stderr.getvalue())
        self.assertIn(
            "checked=3, non_github_urls=2, warnings=1, errors=1",
            stdout.getvalue(),
        )

    def test_main_exits_zero_without_token_or_findings(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        fetcher = Mock(return_value=Mock())
        with patch.object(
            module, "CATALOG", Mock(read_text=Mock(return_value="[]"))
        ), patch.object(module, "github_fetcher", fetcher), patch.object(
            module, "audit", Mock(return_value=([], [], 0, 0))
        ), patch.dict(module.os.environ, {"GITHUB_TOKEN": ""}):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = module.main()
        self.assertEqual(result, 0)
        fetcher.assert_called_once_with(None)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "checked=0, non_github_urls=0, warnings=0, errors=0",
            stdout.getvalue(),
        )

    def test_main_guard_runs_under_main_name(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(
            urllib.request, "build_opener", lambda handler: _ValidOpener()
        ), patch.object(sys, "argv", [str(SCRIPT)]):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("GitHub upstream audit:", stdout.getvalue())
