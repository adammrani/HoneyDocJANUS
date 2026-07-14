"""
src/janus/ci_credential_trap.py
JANUS layer 3 (semi-visible): CI3 fake credentials.

These credentials are bait. They point at our own decoy infrastructure
(decoy_infra.py: fake SSH :2222, fake HTTP :8080). If an attacker exfiltrates
the decoy document and tries to use the credentials, they hit our honeypot and
reveal themselves. The API key embeds the token_id for traceability.
"""

import random
from urllib.parse import urlparse

from src.core.config import get_settings

_settings = get_settings()


def _decoy_host() -> str:
    """Extract the host part of CALLBACK_BASE_URL (attacker-facing bait host)."""
    parsed = urlparse(_settings.CALLBACK_BASE_URL)
    return parsed.hostname or "localhost"


def generate_credentials(doc_type: str, token_id: str) -> dict:
    """
    Return believable fake credentials tailored to the decoy type.

    All network endpoints resolve to our decoy infrastructure so that any use
    attempt is captured. The returned dict maps a label to a value.
    """
    host = _decoy_host()
    short = token_id[:12]

    if doc_type == "financial_report":
        return {
            "Système": "ERP SAP — Module Finance (FI/CO)",
            "URL": f"http://{host}:8080/api/login",
            "Client SAP": "300",
            "Utilisateur": "svc_finance_ro",
            "Mot de passe": f"Fin${short}!",
            "Clé API": f"sap-fi-{token_id}",
        }

    if doc_type == "hr_document":
        return {
            "Système": "Portail RH interne",
            "URL": f"http://{host}:8080/api/login",
            "Utilisateur": "hr.reporting",
            "Mot de passe": f"Rh#{short}2026",
            "Clé API": f"hrportal-{token_id}",
        }

    # technical_config (and default)
    return {
        "Système": "Bastion d'administration",
        "SSH": f"ssh svc_deploy@{host} -p 2222",
        "Mot de passe SSH": f"Dpl0y-{short}",
        "Clé API": f"apikey-{token_id}",
        "Chaîne de connexion DB": (
            f"postgresql://svc_app:Db{random.randint(1000,9999)}@{host}:8080/prod"
        ),
    }


def format_credentials_block(creds: dict) -> str:
    """Format the credentials dict as a monospace text block for the document."""
    lines = ["ANNEXE — ACCÈS SYSTÈMES (RÉSERVÉ ADMINISTRATEURS)", ""]
    for key, value in creds.items():
        lines.append(f"{key:<24}: {value}")
    return "\n".join(lines)
