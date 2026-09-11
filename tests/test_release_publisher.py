from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "publish-github-release.py"
REPOSITORY = "example/archiveweaver"
TAG = "v1.2.3"
TAG_OBJECT_SHA = "a" * 40
SOURCE_REVISION = "b" * 40


class FakeGitHub:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.command_tokens: list[str | None] = []
        self.command_timeouts: list[int | None] = []
        self.release: dict[str, Any] | None = None
        self.release_lookup_error: str | None = None
        self.tag_verified = True
        self.target_revision = SOURCE_REVISION
        self.settings_results = [True]
        self.settings_calls = 0
        self.publish_as_immutable = True

    @staticmethod
    def release_payload(
        *,
        draft: bool,
        immutable: bool,
        assets: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "tag_name": TAG,
            "name": TAG,
            "draft": draft,
            "prerelease": False,
            "immutable": immutable,
            "assets": list(assets),
        }

    @staticmethod
    def asset_record(path: Path) -> dict[str, Any]:
        content = path.read_bytes()
        return {
            "name": path.name,
            "state": "uploaded",
            "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "size": len(content),
        }

    @staticmethod
    def _completed(
        command: Sequence[str],
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    def _settings_enabled(self) -> bool:
        index = min(self.settings_calls, len(self.settings_results) - 1)
        result = self.settings_results[index]
        self.settings_calls += 1
        return result

    def run(self, command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        self.commands.append(argv)
        environment = kwargs.get("env")
        self.command_timeouts.append(kwargs.get("timeout"))
        self.command_tokens.append(
            environment.get("GH_TOKEN") if isinstance(environment, dict) else None
        )
        if argv[:2] == ["gh", "api"]:
            endpoint = argv[2]
            if endpoint == f"repos/{REPOSITORY}/git/ref/tags/{TAG}":
                return self._completed(
                    argv,
                    stdout=json.dumps(
                        {"object": {"type": "tag", "sha": TAG_OBJECT_SHA}}
                    ),
                )
            if endpoint == f"repos/{REPOSITORY}/git/tags/{TAG_OBJECT_SHA}":
                return self._completed(
                    argv,
                    stdout=json.dumps(
                        {
                            "tag": TAG,
                            "verification": {"verified": self.tag_verified},
                            "object": {
                                "type": "commit",
                                "sha": self.target_revision,
                            },
                        }
                    ),
                )
            if endpoint == f"repos/{REPOSITORY}/immutable-releases":
                if not self._settings_enabled():
                    return self._completed(
                        argv,
                        returncode=1,
                        stderr="gh: Not Found (HTTP 404)",
                    )
                return self._completed(
                    argv,
                    stdout=json.dumps(
                        {"enabled": True, "enforced_by_owner": False}
                    ),
                )
            if endpoint == f"repos/{REPOSITORY}/releases/tags/{TAG}":
                if self.release_lookup_error:
                    return self._completed(
                        argv,
                        returncode=1,
                        stderr=self.release_lookup_error,
                    )
                if self.release is None:
                    return self._completed(
                        argv,
                        returncode=1,
                        stderr="gh: Not Found (HTTP 404)",
                    )
                return self._completed(argv, stdout=json.dumps(self.release))
        if argv[:3] == ["gh", "release", "create"]:
            self.release = self.release_payload(
                draft=True,
                immutable=False,
                assets=[],
            )
            return self._completed(argv)
        if argv[:3] == ["gh", "release", "upload"]:
            if self.release is None:
                return self._completed(argv, returncode=1, stderr="missing release")
            self.release["assets"].append(self.asset_record(Path(argv[4])))
            return self._completed(argv)
        if argv[:3] == ["gh", "release", "edit"]:
            if self.release is None:
                return self._completed(argv, returncode=1, stderr="missing release")
            self.release["draft"] = False
            self.release["immutable"] = self.publish_as_immutable
            return self._completed(argv)
        return self._completed(argv, returncode=1, stderr="unexpected fake command")


class ReleasePublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.publisher = runpy.run_path(str(SCRIPT))

    def setUp(self) -> None:
        self.original_directory = Path.cwd()
        self.temporary_directory = tempfile.TemporaryDirectory()
        os.chdir(self.temporary_directory.name)
        Path("dist").mkdir()
        self.wheel = Path("dist/archiveweaver-1.2.3-py3-none-any.whl")
        self.wheel.write_bytes(b"wheel bytes\n")
        self.checksums = Path("SHA256SUMS")
        self.checksums.write_bytes(b"checksum bytes\n")
        self.asset_paths = [self.wheel.as_posix(), self.checksums.as_posix()]

    def tearDown(self) -> None:
        os.chdir(self.original_directory)
        self.temporary_directory.cleanup()

    def publish(
        self,
        fake: FakeGitHub,
        *,
        assets: Sequence[str] | None = None,
        settings_token: str | None = "settings-token",
    ) -> str:
        with patch.object(self.publisher["subprocess"], "run", side_effect=fake.run):
            result = self.publisher["publish_release"](
                repository=REPOSITORY,
                tag=TAG,
                source_revision=SOURCE_REVISION,
                asset_paths=list(assets or self.asset_paths),
                settings_token=settings_token,
            )
        self.assertIsInstance(result, str)
        return result

    def assert_no_clobber(self, fake: FakeGitHub) -> None:
        self.assertFalse(
            any("--clobber" in argument for command in fake.commands for argument in command)
        )

    def test_new_release_is_staged_verified_and_published_immutable(self) -> None:
        fake = FakeGitHub()

        result = self.publish(fake)

        self.assertEqual(result, f"published and verified immutable GitHub Release {TAG}")
        self.assertIsNotNone(fake.release)
        self.assertFalse(fake.release["draft"])
        self.assertTrue(fake.release["immutable"])
        self.assertEqual(
            {asset["name"] for asset in fake.release["assets"]},
            {self.wheel.name, self.checksums.name},
        )
        self.assertEqual(fake.settings_calls, 3)
        self.assertTrue(fake.command_timeouts)
        self.assertEqual(set(fake.command_timeouts), {60})
        self.assertTrue(
            all(
                token == "settings-token"
                for command, token in zip(fake.commands, fake.command_tokens)
                if command[1:3] == ["api", f"repos/{REPOSITORY}/immutable-releases"]
            )
        )
        self.assert_no_clobber(fake)

    def test_github_cli_timeout_fails_without_a_safe_publication_result(self) -> None:
        with patch.object(
            self.publisher["subprocess"],
            "run",
            side_effect=subprocess.TimeoutExpired(["gh", "api"], 60),
        ):
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"], "timed out"
            ):
                self.publisher["_run_gh"](("api", "repos/example/archiveweaver"))

    def test_github_api_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for payload in (
            '{"id": 1, "id": 2}',
            '{"id": NaN}',
            "[" * 2000 + "0" + "]" * 2000,
        ):
            with self.subTest(payload=payload[:40]), patch.object(
                self.publisher["subprocess"],
                "run",
                return_value=subprocess.CompletedProcess(
                    ["gh", "api"],
                    0,
                    payload,
                    "",
                ),
            ):
                with self.assertRaisesRegex(
                    self.publisher["ReleasePublicationError"],
                    "malformed or ambiguous JSON",
                ):
                    self.publisher["_api_object"]("repos/example/archiveweaver")

    def test_exact_existing_immutable_release_is_read_only(self) -> None:
        fake = FakeGitHub()
        fake.release = fake.release_payload(
            draft=False,
            immutable=True,
            assets=[fake.asset_record(self.wheel), fake.asset_record(self.checksums)],
        )

        result = self.publish(fake, settings_token=None)

        self.assertEqual(result, f"verified existing immutable GitHub Release {TAG}")
        self.assertFalse(any(command[1:2] == ["release"] for command in fake.commands))
        self.assertEqual(fake.settings_calls, 0)
        self.assert_no_clobber(fake)

    def test_draft_reuses_exact_asset_and_uploads_only_missing_asset(self) -> None:
        fake = FakeGitHub()
        fake.release = fake.release_payload(
            draft=True,
            immutable=False,
            assets=[fake.asset_record(self.wheel)],
        )

        self.publish(fake)

        uploads = [
            command for command in fake.commands if command[:3] == ["gh", "release", "upload"]
        ]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0][4], self.checksums.as_posix())
        self.assert_no_clobber(fake)

    def test_existing_asset_with_different_content_is_never_replaced(self) -> None:
        fake = FakeGitHub()
        record = fake.asset_record(self.wheel)
        record["digest"] = f"sha256:{'0' * 64}"
        fake.release = fake.release_payload(
            draft=True,
            immutable=False,
            assets=[record],
        )

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "refusing to replace",
        ):
            self.publish(fake)

        self.assertFalse(
            any(command[:3] == ["gh", "release", "upload"] for command in fake.commands)
        )
        self.assertFalse(
            any(command[:3] == ["gh", "release", "edit"] for command in fake.commands)
        )
        self.assert_no_clobber(fake)

    def test_remote_asset_size_must_be_an_integer_not_a_boolean(self) -> None:
        fake = FakeGitHub()
        record = fake.asset_record(self.wheel)
        self.wheel.write_bytes(b"x")
        record["digest"] = f"sha256:{hashlib.sha256(b'x').hexdigest()}"
        record["size"] = True
        fake.release = fake.release_payload(
            draft=True,
            immutable=False,
            assets=[record],
        )

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "refusing to replace"
        ):
            self.publish(fake, assets=[self.wheel.as_posix()])

        self.assertFalse(
            any(command[:3] == ["gh", "release", "edit"] for command in fake.commands)
        )

    def test_published_release_must_be_immutable_and_complete(self) -> None:
        for immutable, assets, message in (
            (False, [fake_asset := FakeGitHub.asset_record(self.wheel)], "not immutable"),
            (True, [fake_asset], "missing assets"),
        ):
            with self.subTest(immutable=immutable):
                fake = FakeGitHub()
                fake.release = fake.release_payload(
                    draft=False,
                    immutable=immutable,
                    assets=assets,
                )
                with self.assertRaisesRegex(
                    self.publisher["ReleasePublicationError"], message
                ):
                    self.publish(fake, settings_token=None)
                self.assertFalse(
                    any(command[1:2] == ["release"] for command in fake.commands)
                )

    def test_ambiguous_release_lookup_fails_without_mutation(self) -> None:
        fake = FakeGitHub()
        fake.release_lookup_error = "gh: route Not Found upstream (HTTP 503)"

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "without a safe recovery"
        ):
            self.publish(fake)

        self.assertFalse(any(command[1:2] == ["release"] for command in fake.commands))

    def test_unsigned_or_wrong_target_tag_fails_without_mutation(self) -> None:
        for verified, target in (
            (False, SOURCE_REVISION),
            (True, "c" * 40),
        ):
            with self.subTest(verified=verified, target=target):
                fake = FakeGitHub()
                fake.tag_verified = verified
                fake.target_revision = target
                with self.assertRaisesRegex(
                    self.publisher["ReleasePublicationError"],
                    "unsigned, unverified, or does not bind",
                ):
                    self.publish(fake)
                self.assertFalse(
                    any(command[1:2] == ["release"] for command in fake.commands)
                )

    def test_unexpected_draft_asset_fails_without_publication(self) -> None:
        fake = FakeGitHub()
        fake.release = fake.release_payload(
            draft=True,
            immutable=False,
            assets=[
                {
                    "name": "unexpected.txt",
                    "state": "uploaded",
                    "digest": f"sha256:{'0' * 64}",
                    "size": 1,
                }
            ],
        )

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "unexpected assets"
        ):
            self.publish(fake)

        self.assertFalse(
            any(command[:3] == ["gh", "release", "edit"] for command in fake.commands)
        )

    def test_disabled_or_unverifiable_immutable_setting_blocks_creation(self) -> None:
        fake = FakeGitHub()
        fake.settings_results = [False]

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "immutable releases are disabled"
        ):
            self.publish(fake)

        self.assertIsNone(fake.release)
        self.assertFalse(any(command[1:2] == ["release"] for command in fake.commands))

    def test_missing_settings_token_blocks_creation(self) -> None:
        fake = FakeGitHub()

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN is required",
        ):
            self.publish(fake, settings_token=None)

        self.assertIsNone(fake.release)
        self.assertFalse(any(command[1:2] == ["release"] for command in fake.commands))

    def test_revoked_immutable_setting_blocks_publication(self) -> None:
        fake = FakeGitHub()
        fake.settings_results = [True, True, False]

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "immutable releases are disabled"
        ):
            self.publish(fake)

        self.assertIsNotNone(fake.release)
        self.assertTrue(fake.release["draft"])
        self.assertEqual(len(fake.release["assets"]), 2)
        self.assertFalse(
            any(command[:3] == ["gh", "release", "edit"] for command in fake.commands)
        )

    def test_mutable_post_publish_state_is_reported_as_a_hard_failure(self) -> None:
        fake = FakeGitHub()
        fake.publish_as_immutable = False

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "published without repository immutability enabled",
        ):
            self.publish(fake)

        self.assertIsNotNone(fake.release)
        self.assertFalse(fake.release["draft"])
        self.assertFalse(fake.release["immutable"])

    def test_release_tag_pattern_requires_canonical_semver(self) -> None:
        pattern = self.publisher["RELEASE_TAG_RE"]
        for valid in (
            "v0.0.0",
            "v1.2.3",
            "v1.2.3-alpha.1",
            "v1.2.3-0A-0+build.007",
        ):
            with self.subTest(valid=valid):
                self.assertIsNotNone(pattern.fullmatch(valid))
        for invalid in (
            "1.2.3",
            "v01.2.3",
            "v1.02.3",
            "v1.2.03",
            "v1.2.3-01",
            "v1.2.3-alpha..1",
            "v1.2.3-",
            "v1.2.3+",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(pattern.fullmatch(invalid))

    def test_unsafe_duplicate_and_symlink_asset_paths_are_rejected_locally(self) -> None:
        outside = Path(self.temporary_directory.name).parent / "outside-release.txt"
        outside.write_bytes(b"outside")
        try:
            for assets, message in (
                (["../outside-release.txt"], "path is unsafe"),
                (
                    [self.wheel.as_posix(), self.wheel.as_posix()],
                    "duplicate release asset name",
                ),
            ):
                with self.subTest(assets=assets):
                    fake = FakeGitHub()
                    with self.assertRaisesRegex(
                        self.publisher["ReleasePublicationError"], message
                    ):
                        self.publish(fake, assets=assets)
                    self.assertEqual(fake.commands, [])

            link = Path("linked-wheel.whl")
            try:
                link.symlink_to(self.wheel.resolve())
            except OSError:
                return
            fake = FakeGitHub()
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"], "contains a symlink"
            ):
                self.publish(fake, assets=[link.as_posix()])
            self.assertEqual(fake.commands, [])
        finally:
            outside.unlink(missing_ok=True)

    def test_hard_linked_and_oversized_release_sets_are_rejected_locally(self) -> None:
        alias = Path("hardlinked-wheel.whl")
        try:
            os.link(self.wheel, alias)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard links are unavailable: {exc}")
        fake = FakeGitHub()
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "exactly one hard link",
        ):
            self.publish(fake, assets=[alias.as_posix()])
        self.assertEqual(fake.commands, [])

        publisher_globals = self.publisher["_local_assets"].__globals__
        limits = {
            "MAX_RELEASE_ASSETS": publisher_globals["MAX_RELEASE_ASSETS"],
            "MAX_RELEASE_ASSET_BYTES": publisher_globals["MAX_RELEASE_ASSET_BYTES"],
            "MAX_RELEASE_TOTAL_BYTES": publisher_globals["MAX_RELEASE_TOTAL_BYTES"],
        }
        try:
            publisher_globals["MAX_RELEASE_ASSETS"] = 1
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"], "asset safety limit"
            ):
                self.publish(FakeGitHub())

            publisher_globals["MAX_RELEASE_ASSETS"] = limits["MAX_RELEASE_ASSETS"]
            publisher_globals["MAX_RELEASE_ASSET_BYTES"] = 1
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"], "byte safety limit"
            ):
                self.publish(FakeGitHub(), assets=[self.checksums.as_posix()])

            publisher_globals["MAX_RELEASE_ASSET_BYTES"] = limits[
                "MAX_RELEASE_ASSET_BYTES"
            ]
            publisher_globals["MAX_RELEASE_TOTAL_BYTES"] = 1
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"], "byte safety limit"
            ):
                self.publish(FakeGitHub(), assets=[self.checksums.as_posix()])
        finally:
            publisher_globals.update(limits)


if __name__ == "__main__":
    unittest.main()
