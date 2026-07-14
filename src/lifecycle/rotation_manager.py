"""
src/lifecycle/rotation_manager.py
Rotate expired honey-documents.

Walks active honeydocs, deactivates those older than their TTL, and asks the
API to regenerate a fresh decoy of the same type so coverage never lapses.
"""

import time
from datetime import datetime, timezone

import requests

from src.core.config import get_settings
from src.core.database import deactivate_honeydoc, list_active_honeydocs
from src.core.logger import log

_settings = get_settings()


def _age_hours(created_at: str) -> float:
    try:
        created = datetime.fromisoformat(created_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.0
    delta = datetime.now(timezone.utc) - created
    return delta.total_seconds() / 3600.0


def check_and_rotate(api_url: str = "") -> dict:
    """
    Deactivate expired honeydocs and request their regeneration.

    Returns a summary: { checked, rotated, regenerated }.
    """
    api_url = api_url or _settings.CALLBACK_BASE_URL
    docs = list_active_honeydocs()
    rotated = 0
    regenerated = 0

    for doc in docs:
        age = _age_hours(doc.get("created_at", ""))
        if age >= float(doc.get("ttl_hours", 72)):
            deactivate_honeydoc(doc["id"])
            rotated += 1
            log.info("HoneyDoc #%s expired (age=%.1fh) — deactivated", doc["id"], age)

            try:
                resp = requests.post(
                    f"{api_url}/generate_decoy",
                    json={
                        "doc_type": doc.get("doc_type", "financial_report"),
                        "target_dir": doc.get("target_dir", ""),
                        "ttl_hours": int(doc.get("ttl_hours", 72)),
                    },
                    timeout=30,
                )
                if resp.ok:
                    regenerated += 1
            except requests.RequestException as exc:
                log.warning("Regeneration request failed for #%s: %s", doc["id"], exc)

    summary = {"checked": len(docs), "rotated": rotated, "regenerated": regenerated}
    log.info("Rotation summary: %s", summary)
    return summary


def run_loop(interval_minutes: int = 30) -> None:
    """Run check_and_rotate forever, every `interval_minutes`."""
    log.info("Rotation manager loop started (interval=%d min)", interval_minutes)
    while True:
        try:
            check_and_rotate()
        except Exception as exc:  # noqa: BLE001 — loop must never die
            log.error("Rotation loop error: %s", exc)
        time.sleep(interval_minutes * 60)


if __name__ == "__main__":
    run_loop()
