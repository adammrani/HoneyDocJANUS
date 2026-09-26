"""
src/lifecycle/rotation_manager.py
Rotate expired honey-documents.

Walks active honeydocs, deactivates those older than their TTL, and asks the
API to regenerate a fresh decoy of the same type so coverage never lapses.
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from src.core.config import get_settings
from src.core.database import (
    deactivate_honeydoc,
    get_token_by_honeydoc_id,
    list_active_honeydocs,
    mark_token_revocation,
)
from src.core.logger import log
from src.detection.canarytoken_handler import (
    CanarytokenProviderError,
    delete_remote_token,
)

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


def _inside_allowed_root(path: Path) -> bool:
    candidate = path.resolve()
    for configured_root in (
        _settings.JANUS_DEPLOY_ROOT,
        _settings.DECOY_DROP_PATH,
    ):
        root = Path(configured_root).resolve()
        try:
            if os.path.commonpath((str(candidate), str(root))) == str(root):
                return True
        except ValueError:
            continue
    return False


def _remove_retired_files(doc: dict) -> int:
    candidates = {
        Path(str(doc.get("filepath") or "")),
        Path(_settings.DECOY_DROP_PATH) / str(doc.get("filename") or ""),
    }
    removed = 0
    for candidate in candidates:
        if not str(candidate) or not _inside_allowed_root(candidate):
            continue
        if candidate.is_file():
            candidate.unlink()
            removed += 1
    return removed


def _revoke_registered_token(honeydoc_id: int) -> str:
    token = get_token_by_honeydoc_id(honeydoc_id)
    if token is None:
        return "not_registered"
    token_id = str(token.get("token_id") or "")
    if token.get("provider") != "canarytokens":
        mark_token_revocation(token_id, status="not_required")
        return "not_required"
    try:
        delete_remote_token(
            token_id,
            str(token.get("auth_token") or ""),
        )
    except CanarytokenProviderError as error:
        mark_token_revocation(
            token_id,
            status="failed",
            error=str(error),
        )
        log.warning("Old Canarytoken revocation failed for HoneyDoc #%s.", honeydoc_id)
        return "failed"
    mark_token_revocation(token_id, status="revoked")
    return "revoked"


def check_and_rotate(api_url: str = "") -> dict:
    """
    Deactivate expired honeydocs and request their regeneration.

    Returns a summary: { checked, rotated, regenerated }.
    """
    api_url = api_url or _settings.CALLBACK_BASE_URL
    docs = list_active_honeydocs()
    rotated = 0
    regenerated = 0
    failed = 0
    revoked = 0
    revocation_failed = 0
    files_removed = 0

    for doc in docs:
        age = _age_hours(doc.get("created_at", ""))
        if age >= float(doc.get("ttl_hours", 72)):
            try:
                headers = (
                    {"X-JANUS-API-Key": _settings.JANUS_ADMIN_API_KEY}
                    if _settings.JANUS_ADMIN_API_KEY
                    else {}
                )
                resp = requests.post(
                    f"{api_url}/generate_decoy",
                    json={
                        "doc_type": doc.get("doc_type", "financial_report"),
                        "output_format": doc.get("file_format", "docx"),
                        "scenario": doc.get("scenario", ""),
                        "target_dir": doc.get("target_dir", ""),
                        "ttl_hours": int(doc.get("ttl_hours", 72)),
                    },
                    headers=headers,
                    timeout=90,
                )
                if resp.ok:
                    revocation = _revoke_registered_token(doc["id"])
                    revoked += int(revocation == "revoked")
                    revocation_failed += int(revocation == "failed")
                    files_removed += _remove_retired_files(doc)
                    deactivate_honeydoc(doc["id"], "ttl_rotation_replaced")
                    rotated += 1
                    regenerated += 1
                    log.info(
                        "HoneyDoc #%s rotated after %.1fh.", doc["id"], age
                    )
                else:
                    failed += 1
                    log.warning(
                        "Regeneration rejected for #%s: HTTP %s",
                        doc["id"],
                        resp.status_code,
                    )
            except requests.RequestException as exc:
                failed += 1
                log.warning("Regeneration request failed for #%s: %s", doc["id"], exc)

    summary = {
        "checked": len(docs),
        "rotated": rotated,
        "regenerated": regenerated,
        "failed": failed,
        "revoked": revoked,
        "revocation_failed": revocation_failed,
        "files_removed": files_removed,
    }
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
