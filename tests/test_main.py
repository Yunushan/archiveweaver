from __future__ import annotations

import runpy
import unittest
from unittest.mock import patch


class MainModuleTests(unittest.TestCase):
    def test_module_entrypoint_propagates_cli_exit_code(self) -> None:
        with patch("archiveweaver.cli.main", return_value=17) as cli_main:
            with self.assertRaises(SystemExit) as raised:
                runpy.run_module("archiveweaver.__main__", run_name="__main__")

        self.assertEqual(raised.exception.code, 17)
        cli_main.assert_called_once_with()
