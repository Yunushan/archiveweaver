from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import runpy
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from collections.abc import Sequence
from unittest.mock import Mock, patch


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
        self.edit_keeps_draft = False

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
                result = self._settings_enabled()
                if result is False:
                    return self._completed(
                        argv,
                        returncode=1,
                        stderr="gh: Not Found (HTTP 404)",
                    )
                if isinstance(result, dict):
                    return self._completed(argv, stdout=json.dumps(result))
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
            if not self.edit_keeps_draft:
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
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "timed out"
        ):
            self.publisher["_run_gh"](("api", "repos/example/archiveweaver"))

    def test_github_api_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for payload in (
            '{"id": 1, "id": 2}',
            '{"id": NaN}',
            '{"id": 1e9999}',
            '{"id": ' + ("9" * 4301) + "}",
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
            ), self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"],
                "malformed or ambiguous JSON",
            ):
                self.publisher["_api_object"]("repos/example/archiveweaver")

    def test_github_api_json_rejects_oversized_responses(self) -> None:
        with patch.dict(
            self.publisher["_api_object"].__globals__, {"MAX_API_JSON_BYTES": 1}
        ), patch.object(
            self.publisher["subprocess"],
            "run",
            return_value=subprocess.CompletedProcess(
                ["gh", "api"],
                0,
                "{}",
                "",
            ),
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "oversized JSON"
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


    def publish_with_api(
        self,
        api: Any,
        *,
        run: Any = None,
        repository: str = REPOSITORY,
        tag: str = TAG,
        source_revision: str = SOURCE_REVISION,
        asset_paths: Sequence[str] | None = None,
        settings_token: str | None = "settings-token",
    ) -> str:
        publish = self.publisher["publish_release"]
        runner = run or (lambda *args, **kwargs: "")
        with patch.dict(
            publish.__globals__, {"_api_object": api, "_run_gh": runner}
        ):
            return publish(
                repository=repository,
                tag=tag,
                source_revision=source_revision,
                asset_paths=list(asset_paths or self.asset_paths),
                settings_token=settings_token,
            )

    @staticmethod
    def api_tag_objects() -> Any:
        def api(endpoint: str, *, allow_not_found: bool = False, token: Any = None) -> Any:
            if "/git/ref/tags/" in endpoint:
                return {"object": {"type": "tag", "sha": TAG_OBJECT_SHA}}
            if "/git/tags/" in endpoint:
                return {
                    "tag": TAG,
                    "verification": {"verified": True},
                    "object": {"type": "commit", "sha": SOURCE_REVISION},
                }
            raise AssertionError(endpoint)

        return api

    def test_json_nesting_rejects_escapes_and_accepts_trailing_closing(self) -> None:
        reject = self.publisher["_reject_excessive_json_nesting"]
        reject(r'{"a": "x\\y"}')
        reject("]")

    def test_run_gh_reports_missing_cli(self) -> None:
        with patch.object(
            self.publisher["subprocess"], "run", side_effect=OSError("no gh")
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "cannot execute the GitHub CLI",
        ):
            self.publisher["_run_gh"](("api", "repos/example/archiveweaver"))

    def test_api_object_rejects_non_object_and_bounds_numbers(self) -> None:
        api = self.publisher["_api_object"]

        def with_payload(payload: str) -> Any:
            return patch.object(
                self.publisher["subprocess"],
                "run",
                return_value=subprocess.CompletedProcess(["gh", "api"], 0, payload, ""),
            )

        with with_payload("[]"), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "non-object API response"
        ):
            api("repos/example/archiveweaver")
        with with_payload('{"value": 1.5}'):
            self.assertEqual(api("repos/example/archiveweaver"), {"value": 1.5})
        with with_payload('{"value": 1.' + "0" * 4300 + "}"):
            with self.assertRaisesRegex(
                self.publisher["ReleasePublicationError"],
                "malformed or ambiguous JSON",
            ):
                api("repos/example/archiveweaver")

    def test_immutable_settings_malformed_shape_blocks_creation(self) -> None:
        tag_api = self.api_tag_objects()

        def api(endpoint: str, *, allow_not_found: bool = False, token: Any = None) -> Any:
            if endpoint.endswith("/immutable-releases"):
                return {"enabled": True, "enforced_by_owner": "yes"}
            if "/releases/tags/" in endpoint:
                return None
            return tag_api(endpoint, allow_not_found=allow_not_found, token=token)

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "malformed or disabled immutable-release settings",
        ):
            self.publish_with_api(api)

    def test_signed_tag_verification_rejects_unavailable_and_malformed_objects(self) -> None:
        validate = self.publisher["_verify_signed_annotated_tag"]
        error = self.publisher["ReleasePublicationError"]

        def run_with(responses: list[Any]) -> None:
            iterator = iter(responses)

            def api(endpoint: str, *, allow_not_found: bool = False, token: Any = None) -> Any:
                return next(iterator)

            with patch.dict(validate.__globals__, {"_api_object": api}):
                validate(REPOSITORY, TAG, SOURCE_REVISION)

        with self.assertRaisesRegex(error, "reference is unavailable"):
            run_with([None])
        with self.assertRaisesRegex(error, "annotated, not lightweight"):
            run_with([{"object": {"type": "commit", "sha": TAG_OBJECT_SHA}}])
        with self.assertRaisesRegex(error, "invalid identity"):
            run_with([{"object": {"type": "tag", "sha": "not-a-sha"}}])
        with self.assertRaisesRegex(error, "tag object is unavailable"):
            run_with([{"object": {"type": "tag", "sha": TAG_OBJECT_SHA}}, None])

    def test_symlink_component_inspection_failure_is_reported(self) -> None:
        with patch.object(
            self.publisher["Path"], "lstat", side_effect=OSError("nope")
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "cannot inspect release asset path",
        ):
            self.publisher["_has_symlink_component"](Path("some-asset.whl"))

    def test_hash_asset_open_failure_is_reported(self) -> None:
        with patch.object(
            self.publisher["os"], "open", side_effect=OSError("denied")
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "cannot open release asset"
        ):
            self.publisher["_hash_asset"](Path("x.whl"))

    @unittest.skipIf(
        os.name == "nt",
        "Windows os.open raises PermissionError for directories instead of reporting a regular-file mismatch",
    )
    def test_hash_asset_requires_a_regular_file(self) -> None:
        directory = Path("asset-directory")
        directory.mkdir()
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "not a regular file"
        ):
            self.publisher["_hash_asset"](directory)

    def test_hash_asset_rejects_stream_growth_beyond_limit(self) -> None:
        hash_asset = self.publisher["_hash_asset"]
        with patch.dict(
            hash_asset.__globals__, {"MAX_RELEASE_ASSET_BYTES": 100}
        ), patch.object(
            self.publisher["os"], "read", side_effect=[b"x" * 200, b""]
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "byte safety limit"
        ):
            hash_asset(self.wheel)

    def test_hash_asset_measurement_oserror_is_reported(self) -> None:
        with patch.object(
            self.publisher["os"], "fstat", side_effect=OSError("bad fd")
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "cannot measure release asset safely",
        ):
            self.publisher["_hash_asset"](self.wheel)

    def test_hash_asset_detects_change_during_hashing(self) -> None:
        before = types.SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o644,
            st_nlink=1,
            st_size=12,
            st_mtime_ns=100,
        )
        after = types.SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o644,
            st_nlink=1,
            st_size=20,
            st_mtime_ns=100,
        )
        with patch.object(
            self.publisher["os"], "read", return_value=b""
        ), patch.object(
            self.publisher["os"], "fstat", side_effect=[before, after]
        ), patch.object(
            self.publisher["os"], "stat", return_value=after
        ), self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "changed while it was being hashed",
        ):
            self.publisher["_hash_asset"](self.wheel)

    def test_local_assets_reject_unsafe_names_and_empty_sets(self) -> None:
        local_assets = self.publisher["_local_assets"]
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "name is unsafe"
        ):
            local_assets(["-bad"])
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "at least one release asset"
        ):
            local_assets([])

    def test_release_identity_validation_rejects_bad_states(self) -> None:
        validate = self.publisher["_validate_release_identity"]
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "identity or state is malformed"
        ):
            validate(
                {
                    "tag_name": "other",
                    "name": TAG,
                    "draft": False,
                    "prerelease": False,
                    "immutable": True,
                    "assets": [],
                },
                TAG,
            )
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "impossible immutable state"
        ):
            validate(
                {
                    "tag_name": TAG,
                    "name": TAG,
                    "draft": True,
                    "prerelease": False,
                    "immutable": True,
                    "assets": [],
                },
                TAG,
            )

    def test_remote_assets_reject_malformed_and_unsafe_records(self) -> None:
        remote_assets = self.publisher["_remote_assets"]
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "malformed asset record"
        ):
            remote_assets({"assets": [1]})
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "unsafe or duplicate asset name"
        ):
            remote_assets({"assets": [{"name": "has space"}]})
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "unsafe or duplicate asset name"
        ):
            remote_assets({"assets": [{"name": "same"}, {"name": "same"}]})

    def test_publish_release_rejects_invalid_arguments(self) -> None:
        publish = self.publisher["publish_release"]
        error = self.publisher["ReleasePublicationError"]
        with self.assertRaisesRegex(error, "owner/name slug"):
            publish(
                repository="not-a-slug",
                tag=TAG,
                source_revision=SOURCE_REVISION,
                asset_paths=self.asset_paths,
            )
        with self.assertRaisesRegex(error, "canonical v-prefixed"):
            publish(
                repository=REPOSITORY,
                tag="1.2.3",
                source_revision=SOURCE_REVISION,
                asset_paths=self.asset_paths,
            )
        with self.assertRaisesRegex(error, "full lowercase"):
            publish(
                repository=REPOSITORY,
                tag=TAG,
                source_revision="NOT-A-SHA",
                asset_paths=self.asset_paths,
            )

    def test_created_release_that_cannot_be_read_back_fails(self) -> None:
        tag_api = self.api_tag_objects()

        def api(endpoint: str, *, allow_not_found: bool = False, token: Any = None) -> Any:
            if endpoint.endswith("/immutable-releases"):
                return {"enabled": True, "enforced_by_owner": False}
            if "/releases/tags/" in endpoint:
                return None
            return tag_api(endpoint, allow_not_found=allow_not_found, token=token)

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "could not be read back"
        ):
            self.publish_with_api(api)

    def test_release_state_change_before_verification_fails(self) -> None:
        tag_api = self.api_tag_objects()
        release_reads = {"count": 0}

        def api(endpoint: str, *, allow_not_found: bool = False, token: Any = None) -> Any:
            if endpoint.endswith("/immutable-releases"):
                return {"enabled": True, "enforced_by_owner": False}
            if "/releases/tags/" in endpoint:
                release_reads["count"] += 1
                if release_reads["count"] == 1:
                    return None
                if release_reads["count"] == 2:
                    return FakeGitHub.release_payload(
                        draft=True, immutable=False, assets=[]
                    )
                return FakeGitHub.release_payload(
                    draft=False, immutable=True, assets=[]
                )
            return tag_api(endpoint, allow_not_found=allow_not_found, token=token)

        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"],
            "changed state before verification",
        ):
            self.publish_with_api(api)

    def test_release_that_remains_draft_after_edit_fails(self) -> None:
        fake = FakeGitHub()
        fake.edit_keeps_draft = True
        with self.assertRaisesRegex(
            self.publisher["ReleasePublicationError"], "did not become published"
        ):
            self.publish(fake)

    def test_parser_reads_environment_defaults(self) -> None:
        parser = self.publisher["_parser"]
        with patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_REF_NAME": TAG,
                "GITHUB_SHA": SOURCE_REVISION,
            },
        ):
            args = parser().parse_args(["a.whl"])
        self.assertEqual(
            (args.repository, args.tag, args.source_revision, args.assets),
            (REPOSITORY, TAG, SOURCE_REVISION, ["a.whl"]),
        )
        with patch.dict(os.environ, {}, clear=True):
            args = parser().parse_args(["b.whl"])
        self.assertIsNone(args.repository)

    def test_main_requires_token_and_reports_failures(self) -> None:
        main = self.publisher["main"]
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                main(
                    [
                        "--repository",
                        REPOSITORY,
                        "--tag",
                        TAG,
                        "--source-revision",
                        SOURCE_REVISION,
                        "asset.whl",
                    ]
                ),
                1,
            )
        error = self.publisher["ReleasePublicationError"]("boom")
        with patch.dict(os.environ, {"GH_TOKEN": "token"}), patch.dict(
            main.__globals__, {"publish_release": Mock(side_effect=error)}
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "--tag",
                        TAG,
                        "--source-revision",
                        SOURCE_REVISION,
                        "asset.whl",
                    ]
                ),
                1,
            )

    def test_main_reports_success(self) -> None:
        main = self.publisher["main"]
        fake = Mock(return_value="published ok")
        output = io.StringIO()
        with patch.dict(os.environ, {"GH_TOKEN": "token"}), patch.dict(
            main.__globals__, {"publish_release": fake}
        ), contextlib.redirect_stdout(output):
            self.assertEqual(
                main(
                    [
                        "--repository",
                        REPOSITORY,
                        "--tag",
                        TAG,
                        "--source-revision",
                        SOURCE_REVISION,
                        "asset.whl",
                    ]
                ),
                0,
            )
        self.assertIn("published ok", output.getvalue())
        self.assertEqual(fake.call_args.kwargs["repository"], REPOSITORY)

    def test_main_guard_runs_and_exits_without_token(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch.object(
            sys, "argv", [str(SCRIPT), "asset.whl"]
        ), self.assertRaises(SystemExit) as context:
            runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(context.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
