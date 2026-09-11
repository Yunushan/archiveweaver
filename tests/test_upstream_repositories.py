from __future__ import annotations

import runpy
import unittest
import urllib.error
from typing import Any


MODULE = runpy.run_path("scripts/validate-upstream-repositories.py")
audit = MODULE["audit"]
github_slug = MODULE["github_slug"]


class UpstreamRepositoryTests(unittest.TestCase):
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
