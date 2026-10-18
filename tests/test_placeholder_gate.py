from __future__ import annotations

import contextlib
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = "scripts/verify-placeholder-free-deploy.py"
MODULE = runpy.run_path(SCRIPT)
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

    def test_directories_and_bytecode_caches_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            cache = deploy / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "cached.yaml").write_text("image: example.invalid/x\n", encoding="utf-8")
            (deploy / "nested").mkdir()
            violations, stale = scan(deploy, {})
            self.assertEqual(violations, [])
            self.assertEqual(stale, [])

    def test_undecodable_files_are_reported_instead_of_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            deploy.mkdir()
            (deploy / "binary.bin").write_bytes(b"\xff\xfe\x00\x01")
            violations, _ = scan(deploy, {})
            self.assertEqual(len(violations), 1)
            self.assertIn("not valid UTF-8", violations[0])


class PlaceholderGateMainTests(unittest.TestCase):
    def _run_main(self, deploy: Path, allowlist: dict[str, str], argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(MODULE["main"].__globals__, {"DEPLOY": deploy, "ALLOWLIST": allowlist}):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = MODULE["main"](argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_usage_rejects_extra_arguments(self) -> None:
        code, _, stderr = self._run_main(Path("deploy"), {}, ["script", "extra"])
        self.assertEqual(code, 2)
        self.assertIn("usage:", stderr)

    def test_clean_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            deploy.mkdir()
            (deploy / "app.yaml").write_text("image: real@sha256:" + "a0" * 32 + "\n", encoding="utf-8")
            code, stdout, stderr = self._run_main(deploy, {}, ["script"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("placeholder gate passed", stdout)

    def test_violations_and_stale_entries_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy"
            deploy.mkdir()
            (deploy / "bad.yaml").write_text("image: example.invalid/x\n", encoding="utf-8")
            (deploy / "tpl.yaml").write_text("name: real\n", encoding="utf-8")
            code, _, stderr = self._run_main(deploy, {"deploy/tpl.yaml": "stale"}, ["script"])
        self.assertEqual(code, 1)
        self.assertIn("placeholder", stderr)
        self.assertIn("allowlisted but no placeholder remains", stderr)

    def test_main_guard_exits_with_the_gate_status(self) -> None:
        with mock.patch.object(sys, "argv", ["verify-placeholder-free-deploy.py", "--help"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(SCRIPT, run_name="__main__")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
