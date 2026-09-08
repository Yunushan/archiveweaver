from __future__ import annotations

import contextlib
import io
import unittest

from archiveweaver.cli import main


class CLITests(unittest.TestCase):
    def test_list_solutions_exposes_ansible_support(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["list-solutions"])
        self.assertEqual(result, 0)
        self.assertIn("Ansible", output.getvalue())

