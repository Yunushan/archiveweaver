from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_PARSER_NESTING = 128


def _reject_excessive_json_nesting(text: str) -> None:
    """Bound nesting before decoder recursion becomes platform-specific."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
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
            if depth > MAX_JSON_PARSER_NESTING:
                raise ValueError("JSON nesting limit exceeds the parser safety limit")
        elif character in "]}" and depth:
            depth -= 1


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys so JSON documents have one meaning."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON numeric constant: {value}")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def load_json_document(text: str) -> Any:
    """Parse JSON while rejecting ambiguous duplicate object keys."""
    _reject_excessive_json_nesting(text)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except RecursionError as exc:
        # Callers apply stricter semantic depth limits after parsing, but the
        # standard decoder can reach Python's recursion boundary first.
        raise ValueError("JSON nesting limit exceeds the parser safety limit") from exc
