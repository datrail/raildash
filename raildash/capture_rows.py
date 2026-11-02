"""Reading a stored capture row, with no database dependency.

The store and the guardrail both need these: the store when it answers an
API with a stored row, the guardrail (and the parsers built on it) when it
judges one. They live here, not on `raildash.store.Store`, so that
`raildash.guardrail`, `body_kinds`, `tool_schemas` and `tool_calls` load
without SQLite or the store, as their docstrings say.
"""

from __future__ import annotations

import json
from typing import Any

from .ingest import redact_credential_headers, redact_raw_event
from .json_safety import JSONStructureTooComplex, check_json_structure

UNSAFE_LEGACY_CAPTURE = {
    "redacted": True,
    "reason": "legacy capture exceeded safe migration limits",
}
MAX_FILE_TYPE_CHARS = 16


def safe_raw(raw: str, *, raw_event: bool = False) -> Any:
    """Parse and redact one stored row without letting it break an API."""
    try:
        check_json_structure(raw)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return UNSAFE_LEGACY_CAPTURE
        return (
            redact_raw_event(parsed)
            if raw_event
            else redact_credential_headers(parsed)
        )
    except (JSONStructureTooComplex, ValueError, RecursionError):
        return UNSAFE_LEGACY_CAPTURE


def file_type(path: str) -> str:
    """A path's lower-cased extension, `(none)` without one."""
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    stem, dot, extension = base.rpartition(".")
    if not dot or not stem or not extension:
        return "(none)"
    if len(extension) >= MAX_FILE_TYPE_CHARS:
        return "(other)"
    return "." + extension.lower()
