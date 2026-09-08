from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CIWorkflowTests(unittest.TestCase):
    def test_github_actions_are_pinned_to_immutable_commit_shas(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        uses_lines = [line.strip() for line in workflow.splitlines() if "uses:" in line]
        self.assertTrue(uses_lines)
        for line in uses_lines:
            self.assertRegex(line, r"uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$")
            self.assertNotRegex(line, r"@[vV][0-9]")
