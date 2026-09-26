"""Canonical serialization helpers for tamper-evident raw evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(payload: Any) -> str:
    """Serialize a JSON-compatible payload deterministically."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def payload_sha256(payload: Any) -> str:
    """Return the SHA-256 of the canonical UTF-8 representation."""

    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
