from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .provider_digest import digest_file


def canonical_hook_argv(argv: list[str]) -> str:
    """Return the serialization used by the Ansible hook boundary."""
    if not argv or not all(isinstance(value, str) and value for value in argv):
        raise ValueError("hook argv must contain non-empty strings")
    if any("\x00" in value or "\r" in value or "\n" in value for value in argv):
        raise ValueError("hook argv must not contain NUL or newline characters")
    return json.dumps(argv, ensure_ascii=True, separators=(",", ":"))


def digest_hook_argv(argv: list[str]) -> str:
    return hashlib.sha256(canonical_hook_argv(argv).encode("utf-8")).hexdigest()


def inspect_hook_command(argv: list[str]) -> dict[str, str | list[str]]:
    canonical = canonical_hook_argv(argv)
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise ValueError("hook executable path must be absolute")
    return {
        "executable": str(executable),
        "executable_sha256": digest_file(executable).removeprefix("sha256:"),
        "argv": argv,
        "canonical_argv": canonical,
        "argv_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
