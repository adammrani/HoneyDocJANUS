"""
src/lifecycle/injector.py
Deploy an assembled artifact: write it, optionally drop it into a target
directory, and persist honeydoc + token rows in the database.
"""

import hashlib
import os
import random
import shutil
from datetime import datetime
from typing import Any

from src.core.config import get_settings
from src.core.database import insert_honeydoc, insert_token
from src.core.logger import log
from src.janus.generators.xlsx_canary import inspect_external_image_beacon

_settings = get_settings()

# Believable filenames per decoy type.
_FILENAMES = {
    ("financial_report", "docx"): [
        "rapport_financier_Q2_2026.docx",
        "budget_previsionnel_confidentiel.docx",
        "note_tresorerie_direction.docx",
        "bilan_intermediaire_2026.docx",
    ],
    ("financial_report", "xlsx"): [
        "budget_previsionnel_confidentiel.xlsx",
        "balance_generale_confidentielle.xlsx",
        "reporting_financier_direction.xlsx",
        "dossier_comptable_annuel.xlsx",
    ],
    ("hr_document", "docx"): [
        "grille_salaires_2026.docx",
        "contrats_cadres_confidentiel.docx",
        "plan_recrutement_H2.docx",
        "evaluations_annuelles.docx",
    ],
    ("technical_config", "docx"): [
        "credentials_prod_backup.docx",
        "config_infrastructure_v3.docx",
        "acces_systemes_admin.docx",
        "notes_deploiement_prod.docx",
    ],
}


def _pick_filename(doc_type: str, output_format: str = "docx") -> str:
    normalized_format = output_format.casefold().lstrip(".")
    if normalized_format not in {"docx", "xlsx"}:
        raise ValueError(f"Format de document non pris en charge : {output_format}")
    candidates = _FILENAMES.get(
        (doc_type, normalized_format),
        [f"document_interne_confidentiel.{normalized_format}"],
    )
    base = random.choice(candidates)
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    name, ext = os.path.splitext(base)
    return f"{name}_{stamp}{ext}"


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def deploy_document(
    doc: Any,
    doc_type: str,
    token_id: str,
    token_url: str,
    callback_url: str,
    token_provider: str = "local",
    token_type: str = "web",
    token_auth_token: str = "",
    token_activation: str = "",
    target_dir: str = "",
    ttl_hours: int = 72,
    strict_target: bool = False,
    output_format: str = "docx",
    scenario: str = "",
    generator_version: str = "janus-docx/1.0",
) -> dict:
    """
    Persist the document and register it in the database.

    Returns:
        { honeydoc_id, filename, deployed_path, token_id, token_url }
    """
    _settings.ensure_dirs()

    filename = _pick_filename(doc_type, output_format)
    stored_path = os.path.join(_settings.DECOY_DROP_PATH, filename)
    doc.save(stored_path)
    if output_format.casefold().lstrip(".") == "xlsx":
        inspection = inspect_external_image_beacon(stored_path)
        if inspection["macro_parts"]:
            raise ValueError("Le classeur généré contient une partie macro interdite.")
        if token_url and not inspection["valid"]:
            raise ValueError(
                "La relation Canarytoken externe est absente du classeur généré."
            )
    log.info("HoneyDoc saved to %s", stored_path)

    # Optionally copy into a live shared directory (simulated share in dev).
    deployed_path = stored_path
    if target_dir and not os.path.isdir(target_dir):
        message = f"Target directory does not exist: {target_dir}"
        if strict_target:
            raise ValueError(message)
        log.warning(message)

    elif target_dir:
        try:
            dest = os.path.join(target_dir, filename)
            shutil.copy2(stored_path, dest)
            deployed_path = dest
            log.info("HoneyDoc dropped into target dir %s", dest)
        except OSError as exc:
            if strict_target:
                raise RuntimeError(
                    f"Could not deploy HoneyDoc to {target_dir}."
                ) from exc
            log.warning("Could not copy to target_dir %s (%s)", target_dir, exc)

    elif strict_target:
        raise ValueError("A target directory is required in strict mode.")

    file_hash = _sha256(deployed_path)
    honeydoc_id = insert_honeydoc(
        filename=filename,
        filepath=deployed_path,
        doc_type=doc_type,
        target_dir=target_dir,
        ttl_hours=ttl_hours,
        file_format=output_format.casefold().lstrip("."),
        scenario=scenario,
        sha256=file_hash,
        generator_version=generator_version,
    )
    insert_token(
        honeydoc_id=honeydoc_id,
        token_id=token_id,
        token_url=token_url,
        callback_url=callback_url,
        provider=token_provider,
        token_type=token_type,
        auth_token=token_auth_token,
        activation_mode=token_activation,
    )

    return {
        "honeydoc_id": honeydoc_id,
        "filename": filename,
        "deployed_path": deployed_path,
        "token_id": token_id,
        "token_url": token_url,
        "file_format": output_format.casefold().lstrip("."),
        "scenario": scenario,
        "sha256": file_hash,
        "generator_version": generator_version,
    }
