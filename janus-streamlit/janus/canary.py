"""Adaptateur Canarytokens : URL fournie ou API officielle compatible V3."""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any
from zipfile import BadZipFile, ZipFile

import requests

from .config import Settings


class CanaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class TokenCredentials:
    token: str
    auth_token: str
    token_url: str
    hostname: str | None
    token_type: str


class CanarytokensClient:
    """Client isolé afin que l'intégration fournisseur reste remplaçable et testable."""

    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.settings = settings
        self.session = session or requests.Session()

    def _endpoint(self, operation: str) -> str:
        api_path = self.settings.canary_api_path.strip("/")
        middle = f"/{api_path}" if api_path else ""
        return f"{self.settings.canary_base_url}{middle}/{operation.lstrip('/')}"

    def create_word_token(self, memo: str, text_snippet: str) -> TokenCredentials:
        if not self.settings.canary_official_configured:
            raise CanaryError(
                "Configurez CANARY_ALERT_EMAIL ou CANARY_WEBHOOK_URL avant d'utiliser le fournisseur officiel."
            )
        payload: dict[str, Any] = {
            "token_type": "ms_word",
            "memo": memo[:255],
            "include_text_snippet": True,
            "text_snippet": text_snippet[:5_000],
        }
        if self.settings.canary_alert_email:
            payload["email"] = self.settings.canary_alert_email
        if self.settings.canary_webhook_url:
            payload["webhook_url"] = self.settings.canary_webhook_url
        try:
            response = self.session.post(
                self._endpoint("generate"),
                json=payload,
                timeout=self.settings.ai_timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise CanaryError(f"Création Canarytoken impossible : {exc}") from exc
        error_message = data.get("error_message") or data.get("error")
        if error_message:
            raise CanaryError(f"Canarytokens a refusé la création : {error_message}")
        if not data.get("token") or not data.get("auth_token"):
            raise CanaryError("Réponse Canarytokens incomplète : token de gestion absent.")
        return TokenCredentials(
            token=str(data["token"]),
            auth_token=str(data["auth_token"]),
            token_url=str(data.get("token_url") or data.get("Url") or ""),
            hostname=str(data["hostname"]) if data.get("hostname") else None,
            token_type=str(data.get("token_type") or "ms_word"),
        )

    def download_word(self, credentials: TokenCredentials) -> bytes:
        try:
            response = self.session.get(
                self._endpoint("download"),
                params={
                    "fmt": "msword",
                    "token": credentials.token,
                    "auth": credentials.auth_token,
                },
                timeout=self.settings.ai_timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise CanaryError(f"Téléchargement Canary impossible : {exc}") from exc
        content = response.content
        validate_official_docx(content, credentials)
        return content

    def history(self, credentials: TokenCredentials) -> dict[str, Any]:
        try:
            response = self.session.get(
                self._endpoint("history"),
                params={"token": credentials.token, "auth": credentials.auth_token},
                timeout=self.settings.ai_timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise CanaryError(f"Lecture de l'historique Canary impossible : {exc}") from exc
        if not isinstance(payload, dict):
            raise CanaryError("Historique Canary inattendu.")
        return payload

    def delete(self, credentials: TokenCredentials) -> None:
        response = self.session.post(
            self._endpoint("delete"),
            json={"token": credentials.token, "auth": credentials.auth_token},
            timeout=self.settings.ai_timeout_seconds,
        )
        response.raise_for_status()


def validate_official_docx(content: bytes, credentials: TokenCredentials) -> None:
    if not content:
        raise CanaryError("Le fournisseur a renvoyé un fichier vide.")
    token_bytes = credentials.token.encode("ascii", errors="ignore")
    try:
        with ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise CanaryError("Le DOCX Canary officiel est incomplet.")
            if any(name.casefold().endswith("vbaproject.bin") for name in names):
                raise CanaryError("Le fournisseur a renvoyé un DOCX contenant une macro.")
            present = any(
                token_bytes in archive.read(name)
                for name in names
                if name and not name.endswith("/")
            )
    except BadZipFile as exc:
        raise CanaryError("Le fournisseur n'a pas renvoyé un DOCX valide.") from exc
    if not present:
        raise CanaryError("La référence au token est absente du DOCX officiel.")


def extract_history_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    history = payload.get("history")
    hits: list[dict[str, Any]] = []
    if isinstance(history, dict) and isinstance(history.get("hits"), list):
        hits = [dict(item) for item in history["hits"] if isinstance(item, dict)]
    elif isinstance(history, dict):
        for timestamp, item in history.items():
            if timestamp == "token_type" or not isinstance(item, dict):
                continue
            hits.append({"time_of_hit": timestamp, **item})
    return hits

