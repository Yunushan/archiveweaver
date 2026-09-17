from __future__ import annotations

import unittest
from unittest.mock import patch

from archiveweaver.json_utils import MAX_JSON_NUMBER_DIGITS, load_json_document


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

        with patch("archiveweaver.json_utils.json.loads", side_effect=RecursionError):
            with self.assertRaisesRegex(ValueError, "parser safety limit"):
                load_json_document("[]")

    def test_parser_rejects_oversized_numeric_tokens_before_conversion(self) -> None:
        for payload in (
            '{"value": ' + ("9" * (MAX_JSON_NUMBER_DIGITS + 1)) + "}",
            '{"value": 0.' + ("1" * (MAX_JSON_NUMBER_DIGITS + 1)) + "}",
        ):
            with self.subTest(payload_length=len(payload)):
                with self.assertRaisesRegex(ValueError, "safety limit"):
                    load_json_document(payload)
