from __future__ import annotations

import io
import os
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-release-actors.py"


class ReleaseActorVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = runpy.run_path(str(SCRIPT), run_name="release_actor_verifier")

    def test_approved_original_and_triggering_actors_pass_case_insensitively(self) -> None:
        self.verifier["verify_release_actors"](
            '["Release-Owner", "Security-Reviewer"]',
            "release-owner",
            "SECURITY-REVIEWER",
        )

    def test_unapproved_original_or_triggering_actor_fails(self) -> None:
        for actor, triggering_actor, expected in (
            ("intruder", "release-owner", "release actor is not approved"),
            ("release-owner", "intruder", "release triggering actor is not approved"),
        ):
            with self.subTest(actor=actor, triggering_actor=triggering_actor):
                with self.assertRaisesRegex(self.verifier["ReleaseActorError"], expected):
                    self.verifier["verify_release_actors"](
                        '["release-owner"]', actor, triggering_actor
                    )

    def test_configuration_must_be_a_nonempty_bounded_json_array(self) -> None:
        invalid_values = (
            "",
            "not-json",
            "{}",
            "[]",
            "[" + ",".join(f'\"actor-{index}\"' for index in range(33)) + "]",
            '"' + ("a" * 4097) + '"',
            "[" * 2000 + "0" + "]" * 2000,
        )
        for value in invalid_values:
            with self.subTest(value=value[:40]):
                with self.assertRaises(self.verifier["ReleaseActorError"]):
                    self.verifier["approved_actors"](value)

    def test_configuration_rejects_invalid_and_case_duplicate_logins(self) -> None:
        for value in (
            '["-owner"]',
            '["owner-"]',
            '["owner_name"]',
            '["owner", 7]',
            '["Owner", "owner"]',
        ):
            with self.subTest(value=value):
                with self.assertRaises(self.verifier["ReleaseActorError"]):
                    self.verifier["approved_actors"](value)

    def test_main_reads_only_the_expected_environment_and_fails_closed(self) -> None:
        environment = {
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON": '["release-owner"]',
            "ARCHIVEWEAVER_RELEASE_ACTOR": "release-owner",
            "ARCHIVEWEAVER_RELEASE_TRIGGERING_ACTOR": "release-owner",
        }
        output = io.StringIO()
        with patch.dict(os.environ, environment, clear=True), redirect_stdout(output):
            self.assertEqual(self.verifier["main"]([]), 0)
        self.assertEqual(output.getvalue().strip(), "release actors authorized")

        diagnostic = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(diagnostic):
            self.assertEqual(self.verifier["main"]([]), 1)
        self.assertIn("release actor authorization error", diagnostic.getvalue())

    def test_main_rejects_arguments(self) -> None:
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic):
            self.assertEqual(self.verifier["main"](["unexpected"]), 2)
        self.assertIn("no arguments are accepted", diagnostic.getvalue())


if __name__ == "__main__":
    unittest.main()
