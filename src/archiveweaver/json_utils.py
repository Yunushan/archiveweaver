from __future__ import annotations

import json
from typing import Any


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys so JSON documents have one meaning."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_document(text: str) -> Any:
    """Parse JSON while rejecting ambiguous duplicate object keys."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
