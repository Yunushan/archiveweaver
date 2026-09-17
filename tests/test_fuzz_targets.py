from __future__ import annotations

import runpy
import unittest


MODULE = runpy.run_path("fuzz/fuzz_targets.py")
exercise_hook_argv = MODULE["exercise_hook_argv"]
exercise_json_document = MODULE["exercise_json_document"]


class FuzzTargetSmokeTests(unittest.TestCase):
    def test_json_target_accepts_valid_and_rejects_malformed_inputs(self) -> None:
        for payload in (
            b'{"safe":[1,true,null]}',
            b'{"duplicate":1,"duplicate":2}',
            b"[" * 256 + b"]" * 256,
            b"\xff\xfe\xfd",
        ):
            with self.subTest(payload=payload[:32]):
                exercise_json_document(payload)

    def test_hook_target_covers_valid_and_rejected_argument_vectors(self) -> None:
        for payload in (
            b"/usr/bin/true\xff--help",
            b"relative\xffargument",
            b"\xff",
            b"/usr/bin/true\xffline\nbreak",
            b"\xff".join([b"value"] * 64),
        ):
            with self.subTest(payload=payload[:32]):
                exercise_hook_argv(payload)
