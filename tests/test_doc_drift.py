from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseStatusDriftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def test_classifier_alpha_matches_readme_and_changelog(self) -> None:
        self.assertIn('"Development Status :: 3 - Alpha"', self.pyproject)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Alpha:", readme.splitlines()[11])
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("remains alpha", changelog)

    def test_coverage_claim_matches_enforced_threshold(self) -> None:
        fail_under = re.findall(r"^fail_under\s*=\s*(\d+)\s*$", self.pyproject, re.MULTILINE)
        self.assertEqual(fail_under, ["100"])
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        claims = re.findall(r"branch coverage\s+to\s+(\d+)%", changelog)
        self.assertEqual(claims, ["100"])

    def test_turkish_readme_claim_matches_existing_file(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertTrue((ROOT / "README.tr.md").is_file())
        self.assertIn("README.tr.md", readme)
        self.assertNotIn("operations summaries", readme)


if __name__ == "__main__":
    unittest.main()
