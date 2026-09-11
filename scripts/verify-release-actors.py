#!/usr/bin/env python3
"""Fail closed unless both GitHub release actors are explicitly approved."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Sequence


LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
MAX_CONFIGURATION_BYTES = 4096
MAX_APPROVED_ACTORS = 32
MAX_CONFIGURATION_JSON_NESTING = 128


class ReleaseActorError(ValueError):
    """Raised when release-actor authorization cannot be proven."""


def _reject_excessive_json_nesting(payload: str) -> None:
    """Reject authorization JSON that exceeds a bounded parser depth."""
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
            if depth > MAX_CONFIGURATION_JSON_NESTING:
                raise ReleaseActorError(
                    "ARCHIVEWEAVER_RELEASE_ACTORS_JSON is not valid JSON"
                )
        elif character in "]}" and depth:
            depth -= 1


def approved_actors(raw_configuration: str) -> frozenset[str]:
    """Parse a bounded JSON array of unique GitHub login names."""

    if not raw_configuration or len(raw_configuration.encode("utf-8")) > MAX_CONFIGURATION_BYTES:
        raise ReleaseActorError(
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON must be a non-empty bounded JSON array"
        )
    _reject_excessive_json_nesting(raw_configuration)
    try:
        value = json.loads(raw_configuration)
    except (ValueError, RecursionError) as exc:
        raise ReleaseActorError(
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON is not valid JSON"
        ) from exc
    if not isinstance(value, list) or not value or len(value) > MAX_APPROVED_ACTORS:
        raise ReleaseActorError(
            "ARCHIVEWEAVER_RELEASE_ACTORS_JSON must contain 1 to 32 GitHub logins"
        )

    normalized: set[str] = set()
    for actor in value:
        if not isinstance(actor, str) or not LOGIN_RE.fullmatch(actor):
            raise ReleaseActorError(
                "ARCHIVEWEAVER_RELEASE_ACTORS_JSON contains an invalid GitHub login"
            )
        identity = actor.casefold()
        if identity in normalized:
            raise ReleaseActorError(
                "ARCHIVEWEAVER_RELEASE_ACTORS_JSON contains a duplicate GitHub login"
            )
        normalized.add(identity)
    return frozenset(normalized)


def verify_release_actors(
    raw_configuration: str,
    actor: str,
    triggering_actor: str,
) -> None:
    """Require the tag-push actor and rerun actor to be independently approved."""

    allowed = approved_actors(raw_configuration)
    identities = (("release actor", actor), ("release triggering actor", triggering_actor))
    for label, identity in identities:
        if not LOGIN_RE.fullmatch(identity):
            raise ReleaseActorError(f"{label} is missing or malformed")
        if identity.casefold() not in allowed:
            raise ReleaseActorError(f"{label} is not approved for production releases")


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("release actor authorization error: no arguments are accepted", file=sys.stderr)
        return 2
    try:
        verify_release_actors(
            os.environ.get("ARCHIVEWEAVER_RELEASE_ACTORS_JSON", ""),
            os.environ.get("ARCHIVEWEAVER_RELEASE_ACTOR", ""),
            os.environ.get("ARCHIVEWEAVER_RELEASE_TRIGGERING_ACTOR", ""),
        )
    except ReleaseActorError as exc:
        print(f"release actor authorization error: {exc}", file=sys.stderr)
        return 1
    print("release actors authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
