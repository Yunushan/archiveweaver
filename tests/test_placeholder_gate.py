from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


MODULE = runpy.run_path("scripts/verify-placeholder-free-deploy.py")
scan = MODULE["scan"]


class PlaceholderGateTests(unittest.TestCase):
    def test_placeholder_in_non_allowlisted_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deploy = root / "deploy"
            deploy.mkdir()
            (deploy / "app.yaml").write_text("image: example.invalid/x\n", encoding="utf-8")
            violations, stale = scan(deploy, {})
            self.assertEqual(len(violations), 1)
            self.assertIn("app.yaml:1", violations[0])
            self.assertEqual(stale, [])

    def test_all_zero_digest_is_detected_but_longer_hex_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            deploy.mkdir()
            (deploy / "zero.yaml").write_text("d: sha256:" + "0" * 64 + "\n", encoding="utf-8")
            (deploy / "ok.yaml").write_text("d: sha256:" + "a0" * 32 + "\n", encoding="utf-8")
            violations, _ = scan(deploy, {})
            self.assertEqual([v.split(":")[0] for v in violations], ["deploy/zero.yaml"])

    def test_allowlisted_template_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deploy = root / "deploy"
            deploy.mkdir()
            (deploy / "tpl.yaml").write_text("name: REPLACE_WITH_NAME\n", encoding="utf-8")
            violations, stale = scan(deploy, {"deploy/tpl.yaml": "template"})
            self.assertEqual(violations, [])
            self.assertEqual(stale, [])

    def test_stale_allowlist_entry_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            deploy.mkdir()
            (deploy / "clean.yaml").write_text("name: real\n", encoding="utf-8")
            violations, stale = scan(deploy, {"deploy/clean.yaml": "no longer a template"})
            self.assertEqual(violations, [])
            self.assertEqual(len(stale), 1)


if __name__ == "__main__":
    unittest.main()
