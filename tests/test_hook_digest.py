from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from archiveweaver.hook_digest import canonical_hook_argv, digest_hook_argv, inspect_hook_command


class HookDigestTests(unittest.TestCase):
    def test_digest_binds_every_argument_without_ambiguity(self) -> None:
        argv = ["/usr/local/bin/archive-check", "--mode", "strict value"]
        canonical = json.dumps(argv, ensure_ascii=True, separators=(",", ":"))
        self.assertEqual(canonical_hook_argv(argv), canonical)
        self.assertEqual(digest_hook_argv(argv), hashlib.sha256(canonical.encode()).hexdigest())
        self.assertNotEqual(digest_hook_argv(argv), digest_hook_argv(argv + ["--force"]))

    def test_inspection_binds_executable_bytes_and_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "reviewed-hook"
            executable.write_bytes(b"reviewed hook bytes\n")
            argv = [str(executable.resolve()), "--safe"]
            result = inspect_hook_command(argv)
            self.assertEqual(
                result["executable_sha256"],
                hashlib.sha256(executable.read_bytes()).hexdigest(),
            )
            self.assertEqual(result["argv_sha256"], digest_hook_argv(argv))

    def test_rejects_relative_empty_and_multiline_argv(self) -> None:
        for argv in ([], ["relative-hook"], ["/bin/hook", "bad\nvalue"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                inspect_hook_command(argv)
