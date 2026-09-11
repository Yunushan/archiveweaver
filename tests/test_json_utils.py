from __future__ import annotations

import unittest

from archiveweaver.json_utils import load_json_document


class JsonDocumentTests(unittest.TestCase):
    def test_parser_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for payload in (
            '{"value": 1, "value": 2}',
            '{"value": NaN}',
            '{"value": Infinity}',
            '{"value": -Infinity}',
            '{"value": 1e9999}',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    load_json_document(payload)

    def test_parser_preserves_finite_standard_json(self) -> None:
        self.assertEqual(
            load_json_document('{"enabled": true, "ratio": 1.25}'),
            {"enabled": True, "ratio": 1.25},
        )

    def test_parser_translates_excessive_decoder_nesting_to_a_value_error(self) -> None:
        payload = "[" * 2000 + "0" + "]" * 2000
        with self.assertRaisesRegex(ValueError, "parser safety limit"):
            load_json_document(payload)
