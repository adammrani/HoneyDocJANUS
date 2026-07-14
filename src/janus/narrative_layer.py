"""
src/janus/narrative_layer.py
JANUS layer 1 (visible): wrap raw LLM content in a believable document frame.

Adds a professional header, a separator line, and a footer carrying an internal
document reference and a classification banner.
"""

import random
from datetime import datetime

_HEADERS = {
    "financial_report": "DIRECTION FINANCIÈRE — DOCUMENT CONFIDENTIEL",
    "hr_document": "DIRECTION DES RESSOURCES HUMAINES — DIFFUSION RESTREINTE",
    "technical_config": "DIRECTION DES SYSTÈMES D'INFORMATION — USAGE INTERNE",
}

_REF_PREFIX = {
    "financial_report": "FIN",
    "hr_document": "RH",
    "technical_config": "DSI",
}

_SEPARATOR = "─" * 60


def _make_reference(doc_type: str) -> str:
    prefix = _REF_PREFIX.get(doc_type, "DOC")
    year = datetime.now().year
    quarter = (datetime.now().month - 1) // 3 + 1
    serial = random.randint(1, 199)
    return f"{prefix}-Q{quarter}-{year}-CONF-{serial:03d}"


def format_narrative(raw_content: str, doc_type: str) -> str:
    """Return the framed document text (header + content + footer)."""
    header = _HEADERS.get(doc_type, "DOCUMENT INTERNE — CONFIDENTIEL")
    reference = _make_reference(doc_type)
    date_str = datetime.now().strftime("%d/%m/%Y")

    footer = (
        f"{_SEPARATOR}\n"
        f"Référence : {reference}    Date : {date_str}\n"
        "CONFIDENTIEL — Ce document est réservé à un usage strictement interne. "
        "Toute diffusion non autorisée est prohibée."
    )

    return f"{header}\n{_SEPARATOR}\n\n{raw_content.strip()}\n\n{footer}"
