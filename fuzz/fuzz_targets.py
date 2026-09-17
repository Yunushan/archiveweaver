from __future__ import annotations

import hashlib
import json

from archiveweaver.hook_digest import canonical_hook_argv, digest_hook_argv
from archiveweaver.json_utils import load_json_document


MAX_JSON_FUZZ_BYTES = 1024 * 1024
MAX_HOOK_FUZZ_BYTES = 64 * 1024
MAX_HOOK_ARGUMENTS = 32


def exercise_json_document(data: bytes) -> None:
    try:
        text = data[:MAX_JSON_FUZZ_BYTES].decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        parsed = load_json_document(text)
    except ValueError:
        return

    canonical = json.dumps(
        parsed,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    reparsed = load_json_document(canonical)
    if reparsed != parsed:
        raise AssertionError("accepted JSON did not survive canonical round-trip")


def exercise_hook_argv(data: bytes) -> None:
    raw_arguments = data[:MAX_HOOK_FUZZ_BYTES].split(
        b"\xff", maxsplit=MAX_HOOK_ARGUMENTS - 1
    )
    argv = [value.decode("utf-8", errors="surrogateescape") for value in raw_arguments]
    try:
        canonical = canonical_hook_argv(argv)
    except ValueError:
        return

    if json.loads(canonical) != argv:
        raise AssertionError("canonical hook argv did not preserve its arguments")
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if digest_hook_argv(argv) != expected:
        raise AssertionError("hook argv digest does not bind the canonical bytes")
