"""Safety checks that prevent generated decoys from revealing their purpose."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable


_FINGERPRINT_PATTERNS = (
    ("janus_brand", re.compile(r"\bjanus\b")),
    ("honey_document", re.compile(r"\bhoney[- ]?doc(?:ument)?s?\b")),
    ("honey_token", re.compile(r"\bhoney[- ]?tokens?\b")),
    ("canary_token", re.compile(r"\bcanary[- ]?tokens?\b")),
    ("cyber_deception", re.compile(r"\bcyber[- ]?deception\b")),
)


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    return "".join(
        character
        for character in decomposed
        if not unicodedata.combining(character)
    ).casefold()


def find_decoy_fingerprints(
    text: str,
    *,
    sensitive_values: Iterable[str] = (),
) -> list[str]:
    """Return evidence labels only; never echo a sensitive value."""

    normalized = _normalized(text)
    findings = [
        label
        for label, pattern in _FINGERPRINT_PATTERNS
        if pattern.search(normalized)
    ]
    normalized_slashes = normalized.replace("\\", "/")
    for value in sensitive_values:
        candidate = _normalized(value).replace("\\", "/").strip()
        if candidate and candidate in normalized_slashes:
            findings.append("sensitive_path")
            break
    return list(dict.fromkeys(findings))
