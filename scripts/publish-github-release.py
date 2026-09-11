#!/usr/bin/env python3
"""Publish a GitHub Release without replacing previously uploaded bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
# GitHub CLI execution is intentional and always uses a validated argv without a shell.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import quote


API_VERSION = "2026-03-10"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RELEASE_TAG_RE = re.compile(
    r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
NOT_FOUND_RE = re.compile(r"\bHTTP\s+404\b", re.IGNORECASE)
GH_COMMAND_TIMEOUT_SECONDS = 60
MAX_RELEASE_ASSETS = 64
MAX_RELEASE_ASSET_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_API_JSON_NESTING = 128


class ReleasePublicationError(RuntimeError):
    """Raised when publication cannot continue without weakening integrity."""


def _reject_excessive_json_nesting(payload: str) -> None:
    """Reject API JSON that exceeds a bounded parser nesting depth."""
    depth = 0
    in_string = False
    escaped = False
    for character in payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_API_JSON_NESTING:
                raise ReleasePublicationError(
                    "GitHub returned malformed or ambiguous JSON"
                )
        elif character in "]}" and depth:
            depth -= 1


@dataclass(frozen=True)
class LocalAsset:
    path: Path
    name: str
    digest: str
    size: int


def _run_gh(
    arguments: Sequence[str],
    *,
    allow_not_found: bool = False,
    token: str | None = None,
) -> str | None:
    command = ["gh", *arguments]
    environment = None
    if token is not None:
        environment = os.environ.copy()
        environment["GH_TOKEN"] = token
    try:
        completed = subprocess.run(  # nosec B603
            command,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=GH_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleasePublicationError(
            "GitHub CLI request timed out without a safe publication result"
        ) from exc
    except OSError as exc:
        raise ReleasePublicationError(f"cannot execute the GitHub CLI: {exc}") from exc
    if completed.returncode == 0:
        return completed.stdout
    diagnostic = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
    if allow_not_found and NOT_FOUND_RE.search(diagnostic):
        return None
    raise ReleasePublicationError(
        f"GitHub CLI request failed without a safe recovery condition: {diagnostic}"
    )


def _api_object(
    endpoint: str,
    *,
    allow_not_found: bool = False,
    token: str | None = None,
) -> dict[str, Any] | None:
    payload = _run_gh(
        (
            "api",
            endpoint,
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
        ),
        allow_not_found=allow_not_found,
        token=token,
    )
    if payload is None:
        return None
    _reject_excessive_json_nesting(payload)

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    def reject_non_finite(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(
            payload,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except (ValueError, RecursionError) as exc:
        raise ReleasePublicationError(
            "GitHub returned malformed or ambiguous JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ReleasePublicationError("GitHub returned a non-object API response")
    return value


def _verify_immutable_releases_enabled(repository: str, settings_token: str | None) -> None:
    if not settings_token:
        raise ReleasePublicationError(
            "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN is required before changing a release"
        )
    settings = _api_object(
        f"repos/{repository}/immutable-releases",
        allow_not_found=True,
        token=settings_token,
    )
    if settings is None:
        raise ReleasePublicationError(
            "immutable releases are disabled or the settings token cannot verify them"
        )
    if (
        settings.get("enabled") is not True
        or not isinstance(settings.get("enforced_by_owner"), bool)
    ):
        raise ReleasePublicationError(
            "GitHub returned malformed or disabled immutable-release settings"
        )


def _verify_signed_annotated_tag(repository: str, tag: str, source_revision: str) -> None:
    encoded_tag = quote(tag, safe="")
    reference = _api_object(f"repos/{repository}/git/ref/tags/{encoded_tag}")
    if reference is None:
        raise ReleasePublicationError("the release tag reference is unavailable")
    reference_object = reference.get("object")
    if not isinstance(reference_object, dict) or reference_object.get("type") != "tag":
        raise ReleasePublicationError("release tag must be annotated, not lightweight")
    tag_object_sha = reference_object.get("sha")
    if not isinstance(tag_object_sha, str) or not SHA_RE.fullmatch(tag_object_sha):
        raise ReleasePublicationError("release tag object has an invalid identity")

    tag_object = _api_object(f"repos/{repository}/git/tags/{tag_object_sha}")
    if tag_object is None:
        raise ReleasePublicationError("the annotated release tag object is unavailable")
    verification = tag_object.get("verification")
    target = tag_object.get("object")
    if (
        tag_object.get("tag") != tag
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != source_revision
    ):
        raise ReleasePublicationError(
            "release tag is unsigned, unverified, or does not bind the workflow commit"
        )


def _has_symlink_component(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts:
        if part == absolute.anchor:
            continue
        current /= part
        try:
            observed = current.lstat()
            attributes = getattr(observed, "st_file_attributes", 0)
            if stat.S_ISLNK(observed.st_mode) or bool(
                attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                return True
        except OSError as exc:
            raise ReleasePublicationError(f"cannot inspect release asset path {path}: {exc}") from exc
    return False


def _hash_asset(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleasePublicationError(f"cannot open release asset {path}: {exc}") from exc
    digest = hashlib.sha256()
    measured = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleasePublicationError(f"release asset is not a regular file: {path}")
        if before.st_nlink != 1:
            raise ReleasePublicationError(
                f"release asset must have exactly one hard link: {path}"
            )
        if before.st_size > MAX_RELEASE_ASSET_BYTES:
            raise ReleasePublicationError(
                f"release asset exceeds the {MAX_RELEASE_ASSET_BYTES}-byte safety limit: {path}"
            )
        while chunk := os.read(descriptor, 1024 * 1024):
            measured += len(chunk)
            if measured > MAX_RELEASE_ASSET_BYTES:
                raise ReleasePublicationError(
                    f"release asset exceeds the {MAX_RELEASE_ASSET_BYTES}-byte safety limit: {path}"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ReleasePublicationError(
            f"cannot measure release asset safely {path}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
    )
    path_identity = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_mode,
        path_after.st_nlink,
        path_after.st_size,
        path_after.st_mtime_ns,
    )
    if (
        identity_before != identity_after
        or identity_after != path_identity
        or after.st_nlink != 1
        or measured != after.st_size
        or _has_symlink_component(path)
    ):
        raise ReleasePublicationError(f"release asset changed while it was being hashed: {path}")
    return f"sha256:{digest.hexdigest()}", measured


def _local_assets(raw_paths: Sequence[str]) -> dict[str, LocalAsset]:
    if len(raw_paths) > MAX_RELEASE_ASSETS:
        raise ReleasePublicationError(
            f"release exceeds the {MAX_RELEASE_ASSETS}-asset safety limit"
        )
    assets: dict[str, LocalAsset] = {}
    total_bytes = 0
    for raw_path in raw_paths:
        path = Path(raw_path)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in raw_path
            or "\x00" in raw_path
            or "\n" in raw_path
            or "\r" in raw_path
        ):
            raise ReleasePublicationError(f"release asset path is unsafe: {raw_path!r}")
        if not ASSET_NAME_RE.fullmatch(path.name):
            raise ReleasePublicationError(f"release asset name is unsafe: {path.name!r}")
        if path.name in assets:
            raise ReleasePublicationError(f"duplicate release asset name: {path.name}")
        if _has_symlink_component(path):
            raise ReleasePublicationError(f"release asset path contains a symlink: {path}")
        digest, size = _hash_asset(path)
        total_bytes += size
        if total_bytes > MAX_RELEASE_TOTAL_BYTES:
            raise ReleasePublicationError(
                f"release assets exceed the {MAX_RELEASE_TOTAL_BYTES}-byte safety limit"
            )
        assets[path.name] = LocalAsset(path=path, name=path.name, digest=digest, size=size)
    if not assets:
        raise ReleasePublicationError("at least one release asset is required")
    return assets


def _validate_release_identity(release: dict[str, Any], tag: str) -> bool:
    if (
        release.get("tag_name") != tag
        or release.get("name") != tag
        or not isinstance(release.get("draft"), bool)
        or not isinstance(release.get("immutable"), bool)
        or release.get("prerelease") is not False
        or not isinstance(release.get("assets"), list)
    ):
        raise ReleasePublicationError("GitHub Release identity or state is malformed")
    is_draft = bool(release["draft"])
    if is_draft and release["immutable"] is not False:
        raise ReleasePublicationError("GitHub Release draft has an impossible immutable state")
    return is_draft


def _remote_assets(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {}
    for item in release["assets"]:
        if not isinstance(item, dict):
            raise ReleasePublicationError("GitHub Release contains a malformed asset record")
        name = item.get("name")
        if not isinstance(name, str) or not ASSET_NAME_RE.fullmatch(name) or name in assets:
            raise ReleasePublicationError("GitHub Release contains an unsafe or duplicate asset name")
        assets[name] = item
    return assets


def _missing_assets(
    expected: dict[str, LocalAsset],
    release: dict[str, Any],
    *,
    allow_missing: bool,
) -> list[LocalAsset]:
    actual = _remote_assets(release)
    unexpected = sorted(set(actual) - set(expected))
    if unexpected:
        raise ReleasePublicationError(
            "GitHub Release contains unexpected assets: " + ", ".join(unexpected)
        )
    missing: list[LocalAsset] = []
    for name, local in sorted(expected.items()):
        remote = actual.get(name)
        if remote is None:
            missing.append(local)
            continue
        if (
            remote.get("state") != "uploaded"
            or remote.get("digest") != local.digest
            or isinstance(remote.get("size"), bool)
            or not isinstance(remote.get("size"), int)
            or remote.get("size") != local.size
        ):
            raise ReleasePublicationError(
                f"refusing to replace GitHub Release asset with different content: {name}"
            )
    if missing and not allow_missing:
        raise ReleasePublicationError(
            "published GitHub Release is missing assets: "
            + ", ".join(asset.name for asset in missing)
        )
    return missing


def publish_release(
    *,
    repository: str,
    tag: str,
    source_revision: str,
    asset_paths: Sequence[str],
    settings_token: str | None = None,
) -> str:
    repository_parts = repository.split("/", maxsplit=1)
    if (
        not REPOSITORY_RE.fullmatch(repository)
        or any(part in {".", ".."} for part in repository_parts)
    ):
        raise ReleasePublicationError("repository must be an owner/name slug")
    if not RELEASE_TAG_RE.fullmatch(tag):
        raise ReleasePublicationError("release tag must be a canonical v-prefixed semantic version")
    if not SHA_RE.fullmatch(source_revision):
        raise ReleasePublicationError(
            "source revision must be a full lowercase 40- or 64-character commit SHA"
        )

    expected = _local_assets(asset_paths)
    _verify_signed_annotated_tag(repository, tag, source_revision)
    endpoint = f"repos/{repository}/releases/tags/{quote(tag, safe='')}"
    release = _api_object(endpoint, allow_not_found=True)
    if release is None:
        _verify_immutable_releases_enabled(repository, settings_token)
        _run_gh(
            (
                "release",
                "create",
                tag,
                "--repo",
                repository,
                "--draft",
                "--verify-tag",
                "--title",
                tag,
                "--notes-from-tag",
            )
        )
        release = _api_object(endpoint)
        if release is None:
            raise ReleasePublicationError("created GitHub Release could not be read back")

    is_draft = _validate_release_identity(release, tag)
    if not is_draft:
        if release.get("immutable") is not True:
            raise ReleasePublicationError("published GitHub Release is not immutable")
        _missing_assets(expected, release, allow_missing=False)
        return f"verified existing immutable GitHub Release {tag}"

    _verify_immutable_releases_enabled(repository, settings_token)
    for asset in _missing_assets(expected, release, allow_missing=True):
        _run_gh(("release", "upload", tag, str(asset.path), "--repo", repository))

    release = _api_object(endpoint)
    if release is None or not _validate_release_identity(release, tag):
        raise ReleasePublicationError("GitHub Release draft changed state before verification")
    _missing_assets(expected, release, allow_missing=False)
    _verify_immutable_releases_enabled(repository, settings_token)
    _run_gh(("release", "edit", tag, "--repo", repository, "--draft=false", "--verify-tag"))

    published = _api_object(endpoint)
    if published is None or _validate_release_identity(published, tag):
        raise ReleasePublicationError("GitHub Release did not become published")
    if published.get("immutable") is not True:
        raise ReleasePublicationError(
            "GitHub Release was published without repository immutability enabled"
        )
    _missing_assets(expected, published, allow_missing=False)
    return f"published and verified immutable GitHub Release {tag}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME"))
    parser.add_argument("--source-revision", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("assets", nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not os.environ.get("GH_TOKEN"):
        print("release publication error: GH_TOKEN is required", file=sys.stderr)
        return 1
    try:
        result = publish_release(
            repository=args.repository or "",
            tag=args.tag or "",
            source_revision=args.source_revision or "",
            asset_paths=args.assets,
            settings_token=os.environ.get("ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"),
        )
    except ReleasePublicationError as exc:
        print(f"release publication error: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
