"""
src/lifecycle/injector.py
Deploy an assembled Document: write the .docx, optionally drop it into a target
directory, and persist honeydoc + token rows in the database.
"""

import os
import random
import shutil
from datetime import datetime

from docx import Document

from src.core.config import get_settings
from src.core.database import insert_honeydoc, insert_token
from src.core.logger import log

_settings = get_settings()

# Believable filenames per decoy type.
_FILENAMES = {
    "financial_report": [
        "rapport_financier_Q2_2026.docx",
        "budget_previsionnel_confidentiel.docx",
        "note_tresorerie_direction.docx",
        "bilan_intermediaire_2026.docx",
    ],
    "hr_document": [
        "grille_salaires_2026.docx",
        "contrats_cadres_confidentiel.docx",
        "plan_recrutement_H2.docx",
        "evaluations_annuelles.docx",
    ],
    "technical_config": [
        "credentials_prod_backup.docx",
        "config_infrastructure_v3.docx",
        "acces_systemes_admin.docx",
        "notes_deploiement_prod.docx",
    ],
}


def _pick_filename(doc_type: str) -> str:
    candidates = _FILENAMES.get(doc_type, ["document_interne_confidentiel.docx"])
    base = random.choice(candidates)
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    name, ext = os.path.splitext(base)
    return f"{name}_{stamp}{ext}"


def deploy_document(
    doc: Document,
    doc_type: str,
    token_id: str,
    token_url: str,
    callback_url: str,
    target_dir: str = "",
    ttl_hours: int = 72,
) -> dict:
    """
    Persist the document and register it in the database.

    Returns:
        { honeydoc_id, filename, deployed_path, token_id, token_url }
    """
    _settings.ensure_dirs()

    filename = _pick_filename(doc_type)
    stored_path = os.path.join(_settings.DECOY_DROP_PATH, filename)
    doc.save(stored_path)
    log.info("HoneyDoc saved to %s", stored_path)

    # Optionally copy into a live shared directory (simulated share in dev).
    deployed_path = stored_path
    if target_dir and os.path.isdir(target_dir):
        try:
            dest = os.path.join(target_dir, filename)
            shutil.copy2(stored_path, dest)
            deployed_path = dest
            log.info("HoneyDoc dropped into target dir %s", dest)
        except OSError as exc:
            log.warning("Could not copy to target_dir %s (%s)", target_dir, exc)

    honeydoc_id = insert_honeydoc(
        filename=filename,
        filepath=deployed_path,
        doc_type=doc_type,
        target_dir=target_dir,
        ttl_hours=ttl_hours,
    )
    insert_token(honeydoc_id, token_id, token_url, callback_url)

    return {
        "honeydoc_id": honeydoc_id,
        "filename": filename,
        "deployed_path": deployed_path,
        "token_id": token_id,
        "token_url": token_url,
    }
