from __future__ import annotations

import contextlib
import io
import json
import runpy
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch


MODULE = runpy.run_path("scripts/validate-upstream-repositories.py")
audit = MODULE["audit"]
github_slug = MODULE["github_slug"]
github_fetcher = MODULE["github_fetcher"]
no_redirect_handler = MODULE["_NoRedirectHandler"]


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


class UpstreamRepositoryTests(unittest.TestCase):
    def test_github_fetcher_rejects_ambiguous_or_unsafe_json(self) -> None:
        fetch = github_fetcher(None)
        for payload in (
            b'{"full_name": "example/repo", "full_name": "other/repo"}',
            b'{"full_name": NaN}',
            b'{"full_name": 1e9999}',
            b'{"full_name": ' + (b"9" * 4301) + b"}",
            b"[" * 2000 + b"0" + b"]" * 2000,
        ):
            with self.subTest(payload=payload[:40]), patch.dict(
                github_fetcher.__globals__,
                {"_open_github_request": Mock(return_value=_Response(payload))},
            ), self.assertRaisesRegex(ValueError, "malformed JSON"):
                fetch("example/repo")

    def test_github_fetcher_does_not_follow_redirects(self) -> None:
        handler = no_redirect_handler()
        request = MODULE["urllib"].request.Request("https://api.github.com/repos/example/repo")
        self.assertIsNone(
            handler.redirect_request(
                request,
                object(),
                302,
                "Found",
                {},
                "https://example.org/redirected",
            )
        )
        fetch = github_fetcher(None)
        redirect = urllib.error.HTTPError(
            request.full_url,
            302,
            "Found",
            {},
            None,
        )
        opened = Mock(side_effect=redirect)
        with patch.dict(github_fetcher.__globals__, {"_open_github_request": opened}):
            with self.assertRaises(urllib.error.HTTPError):
                fetch("example/repo")
        opened.assert_called_once()

    def test_github_fetcher_rejects_oversized_json_before_materializing_it(self) -> None:
        fetch = github_fetcher(None)
        with patch.dict(github_fetcher.__globals__, {"MAX_API_JSON_BYTES": 1}):
            with patch.dict(
                github_fetcher.__globals__,
                {"_open_github_request": Mock(return_value=_Response(b"{}"))},
            ):
                with self.assertRaisesRegex(ValueError, "oversized JSON"):
                    fetch("example/repo")

    def test_github_slug_accepts_only_canonical_https_repository_urls(self) -> None:
        self.assertEqual(
            github_slug("https://github.com/inveniosoftware/invenio-app-rdm"),
            "inveniosoftware/invenio-app-rdm",
        )
        self.assertEqual(github_slug("https://github.com/org/repo.git"), "org/repo")
        for rejected in (
            "http://github.com/org/repo",
            "https://user@github.com/org/repo",
            "https://github.com:invalid/org/repo",
            "https://github.com/org/repo/tree/main",
            "https://github.com/org/repo?tab=readme",
            "https://gitlab.com/org/repo",
            7,
        ):
            self.assertIsNone(github_slug(rejected))

    def test_audit_accepts_live_and_disclosed_archived_repositories(self) -> None:
        solutions = [
            {
                "id": "active",
                "upstream_repo": "https://github.com/example/active",
                "source_repo": "https://github.com/example/active",
                "notes": [],
            },
            {
                "id": "legacy",
                "upstream_repo": "https://github.com/example/legacy",
                "source_repo": "https://sourceforge.net/projects/legacy/",
                "notes": ["The canonical repository is archived and maintenance-only."],
            },
            {
                "id": "external",
                "upstream_repo": "https://example.org/source",
                "source_repo": "https://example.org/source",
                "notes": [],
            },
        ]

        def fetch(slug: str) -> dict[str, Any]:
            return {
                "full_name": slug,
                "disabled": False,
                "archived": slug.endswith("legacy"),
                "pushed_at": None,
            }

        errors, warnings, checked, non_github = audit(solutions, fetch)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertEqual((checked, non_github), (2, 2))

    def test_audit_fails_closed_for_repository_drift_and_bad_metadata(self) -> None:
        solutions = [
            {
                "id": "broken",
                "upstream_repo": "https://github.com/example/broken",
                "source_repo": "https://github.com/example/broken",
                "notes": [],
            },
            {
                "id": "missing",
                "upstream_repo": "https://github.com/example/missing",
                "source_repo": "https://github.com/example/missing",
                "notes": [],
            },
            {
                "id": "noncanonical",
                "upstream_repo": "https://github.com/example/repo/tree/main",
                "source_repo": "https://example.org/source",
                "notes": [],
            },
        ]

        def fetch(slug: str) -> dict[str, Any]:
            if slug.endswith("missing"):
                raise urllib.error.URLError("not found")
            return {
                "full_name": "moved/elsewhere",
                "disabled": True,
                "archived": True,
                "pushed_at": "not-a-timestamp",
            }

        errors, _, checked, non_github = audit(solutions, fetch)
        combined = "\n".join(errors)
        self.assertIn("could not be verified", combined)
        self.assertIn("unexpected repository", combined)
        self.assertIn("disabled", combined)
        self.assertIn("archived but the catalog does not disclose it", combined)
        self.assertIn("invalid pushed_at", combined)
        self.assertIn("non-canonical GitHub repository URL", combined)
        self.assertEqual((checked, non_github), (2, 1))

    def test_open_github_request_builds_a_noredirect_opener(self) -> None:
        opener = Mock()
        opener.open.return_value = "response"
        request = MODULE["urllib"].request.Request(
            "https://api.github.com/repos/example/repo"
        )
        with patch.object(
            MODULE["urllib"].request, "build_opener", return_value=opener
        ):
            result = MODULE["_open_github_request"](request, 7)
        self.assertEqual(result, "response")
        opener.open.assert_called_once_with(request, timeout=7)

    def test_github_slug_rejects_invalid_owner_and_repository(self) -> None:
        self.assertIsNone(github_slug("https://github.com/-org/repo"))
        self.assertIsNone(github_slug("https://github.com/org/."))
        self.assertIsNone(github_slug("https://github.com/org/.."))

    def test_json_nesting_rejects_escapes(self) -> None:
        reject = MODULE["_reject_excessive_json_nesting"]
        reject(r'{"a": "x\\y"}', "example/repo")
        reject("]", "example/repo")

    def test_json_number_and_key_guards_accept_and_reject(self) -> None:
        self.assertEqual(MODULE["_reject_oversized_json_integer"]("5"), 5)
        with self.assertRaises(ValueError):
            MODULE["_reject_oversized_json_integer"]("9" * 4301)
        self.assertEqual(
            MODULE["_reject_oversized_or_non_finite_json_float"]("1.5"), 1.5
        )
        with self.assertRaises(ValueError):
            MODULE["_reject_oversized_or_non_finite_json_float"]("1." + "0" * 4300)
        with self.assertRaises(ValueError):
            MODULE["_reject_oversized_or_non_finite_json_float"]("1e9999")
        self.assertEqual(MODULE["_reject_duplicate_json_keys"]([("a", 1)]), {"a": 1})
        with self.assertRaises(ValueError):
            MODULE["_reject_duplicate_json_keys"]([("a", 1), ("a", 2)])
        with self.assertRaises(ValueError):
            MODULE["_reject_non_finite_json_constant"]("Infinity")

    def test_load_api_json_rejects_non_byte_chunks(self) -> None:
        response = Mock()
        response.read.return_value = "not bytes"
        with self.assertRaisesRegex(ValueError, "non-byte response"):
            MODULE["_load_api_json"](response, "example/repo")

    def test_github_fetcher_uses_token_and_rejects_non_object(self) -> None:
        captured: dict[str, Any] = {}

        def fake_open(request: Any, timeout: int) -> _Response:
            captured["request"] = request
            return _Response(b"[]")

        fetch = github_fetcher("secret")
        with patch.dict(github_fetcher.__globals__, {"_open_github_request": fake_open}):
            with self.assertRaisesRegex(ValueError, "non-object"):
                fetch("example/repo")
        self.assertEqual(
            captured["request"].get_header("Authorization"), "Bearer secret"
        )

    def test_github_fetcher_returns_repository_object(self) -> None:
        fetch = github_fetcher(None)
        with patch.dict(
            github_fetcher.__globals__,
            {
                "_open_github_request": Mock(
                    return_value=_Response(b'{"full_name": "example/repo"}')
                )
            },
        ):
            self.assertEqual(fetch("example/repo"), {"full_name": "example/repo"})

    def test_github_fetcher_reports_when_retry_loop_is_not_entered(self) -> None:
        fetch = github_fetcher(None)
        with patch.dict(github_fetcher.__globals__, {"range": lambda _stop: []}):
            with self.assertRaisesRegex(RuntimeError, "GitHub request failed"):
                fetch("example/repo")

    def test_github_fetcher_retries_url_errors_then_raises(self) -> None:
        fetch = github_fetcher(None)
        opened = Mock(side_effect=urllib.error.URLError("down"))
        with patch.dict(
            github_fetcher.__globals__, {"_open_github_request": opened}
        ), patch.object(MODULE["time"], "sleep") as sleep:
            with self.assertRaises(urllib.error.URLError):
                fetch("example/repo")
        self.assertEqual(opened.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_github_fetcher_retries_server_errors_then_raises(self) -> None:
        fetch = github_fetcher(None)

        def server_error(request: Any, timeout: int) -> Any:
            raise urllib.error.HTTPError(
                "https://api.github.com/repos/example/repo", 500, "Server Error", {}, None
            )

        opened = Mock(side_effect=server_error)
        with patch.dict(
            github_fetcher.__globals__, {"_open_github_request": opened}
        ), patch.object(MODULE["time"], "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                fetch("example/repo")
        self.assertEqual(opened.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_audit_handles_non_string_and_unparsable_urls(self) -> None:
        solutions = [
            {"id": "none", "upstream_repo": None, "source_repo": None, "notes": []},
            {
                "id": "badurl",
                "upstream_repo": "http://[::1",
                "source_repo": "http://[::1",
                "notes": [],
            },
        ]
        errors, warnings, checked, non_github = audit(solutions, lambda slug: {})
        self.assertEqual((errors, warnings, checked), ([], [], 0))
        self.assertEqual(non_github, 1)

    def test_audit_reports_stale_and_recent_push_ages(self) -> None:
        recent = datetime.now(timezone.utc).isoformat()
        solutions = [
            {
                "id": "old",
                "upstream_repo": "https://github.com/example/old",
                "source_repo": "https://github.com/example/old",
                "notes": [],
            },
            {
                "id": "new",
                "upstream_repo": "https://github.com/example/new",
                "source_repo": "https://github.com/example/new",
                "notes": [],
            },
        ]

        def fetch(slug: str) -> dict[str, Any]:
            return {
                "full_name": slug,
                "disabled": False,
                "archived": False,
                "pushed_at": "2000-01-01T00:00:00Z"
                if slug.endswith("old")
                else recent,
            }

        errors, warnings, checked, _ = audit(solutions, fetch)
        self.assertEqual(errors, [])
        self.assertTrue(any("no push for" in warning for warning in warnings))
        self.assertEqual(checked, 2)

    def test_main_reports_catalog_load_and_shape_failures(self) -> None:
        main = MODULE["main"]
        with patch.dict(
            main.__globals__, {"CATALOG": Path("missing-catalog.json")}
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 2)
        with tempfile.TemporaryDirectory() as temporary:
            not_list = Path(temporary) / "not-list.json"
            not_list.write_text('{"a": 1}', encoding="utf-8")
            with patch.dict(
                main.__globals__, {"CATALOG": not_list}
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(), 2)
            bad_items = Path(temporary) / "bad-items.json"
            bad_items.write_text('["x"]', encoding="utf-8")
            with patch.dict(
                main.__globals__, {"CATALOG": bad_items}
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(), 2)

    def test_main_reports_warnings_and_errors(self) -> None:
        main = MODULE["main"]
        solutions = [
            {
                "id": "hidden",
                "upstream_repo": "https://github.com/example/hidden",
                "source_repo": "https://github.com/example/hidden",
                "notes": [],
            },
            {
                "id": "disclosed",
                "upstream_repo": "https://github.com/example/disclosed",
                "source_repo": "https://github.com/example/disclosed",
                "notes": ["The repository is archived and maintenance-only."],
            },
        ]

        def fetch(slug: str) -> dict[str, Any]:
            return {
                "full_name": slug,
                "disabled": False,
                "archived": True,
                "pushed_at": datetime.now(timezone.utc).isoformat(),
            }

        with tempfile.TemporaryDirectory() as temporary:
            catalog = Path(temporary) / "solutions.json"
            catalog.write_text(json.dumps(solutions), encoding="utf-8")
            diagnostics = io.StringIO()
            summary = io.StringIO()
            with patch.dict(
                main.__globals__,
                {"CATALOG": catalog, "github_fetcher": lambda token: fetch},
            ), contextlib.redirect_stderr(diagnostics), contextlib.redirect_stdout(
                summary
            ):
                self.assertEqual(main(), 1)
        self.assertIn("warning:", diagnostics.getvalue())
        self.assertIn("error:", diagnostics.getvalue())
        self.assertIn("errors=1", summary.getvalue())

    def test_main_reports_a_clean_audit(self) -> None:
        main = MODULE["main"]
        solutions = [
            {
                "id": "ok",
                "upstream_repo": "https://github.com/example/ok",
                "source_repo": "https://github.com/example/ok",
                "notes": [],
            }
        ]

        def fetch(slug: str) -> dict[str, Any]:
            return {
                "full_name": slug,
                "disabled": False,
                "archived": False,
                "pushed_at": datetime.now(timezone.utc).isoformat(),
            }

        with tempfile.TemporaryDirectory() as temporary:
            catalog = Path(temporary) / "solutions.json"
            catalog.write_text(json.dumps(solutions), encoding="utf-8")
            diagnostics = io.StringIO()
            with patch.dict(
                main.__globals__,
                {"CATALOG": catalog, "github_fetcher": lambda token: fetch},
            ), contextlib.redirect_stderr(diagnostics):
                self.assertEqual(main(), 0)
        self.assertEqual(diagnostics.getvalue(), "")

    def test_main_guard_runs_and_exits_on_catalog_failure(self) -> None:
        with patch.object(
            Path, "read_text", side_effect=OSError("missing")
        ), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as context:
                runpy.run_path(
                    "scripts/validate-upstream-repositories.py", run_name="__main__"
                )
        self.assertEqual(context.exception.code, 2)
