"""Configuration locale explicite, sans secret implicite ni écrasement d'environnement."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    pass


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(f"Ligne .env invalide ({line_number}).")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if not name:
            raise ConfigurationError(f"Nom vide dans .env ({line_number}).")
        os.environ.setdefault(name, value)


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name, str(default)).strip().casefold()
    if raw in {"1", "true", "yes", "on", "oui"}:
        return True
    if raw in {"0", "false", "no", "off", "non"}:
        return False
    raise ConfigurationError(f"{name} doit être un booléen.")


def _port(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} doit être un port numérique.") from exc
    if not 1 <= value <= 65535:
        raise ConfigurationError(f"{name} doit être compris entre 1 et 65535.")
    return value


def _positive_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} doit être un nombre.") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} doit être positif.")
    return value


def validate_http_url(name: str, value: str, *, allow_empty: bool = False) -> str:
    value = value.strip()
    if not value and allow_empty:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(f"{name} doit être une URL HTTP(S) complète.")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    project_dir: Path
    data_dir: Path
    database_path: Path
    generated_dir: Path
    api_host: str
    api_port: int
    streamlit_host: str
    streamlit_port: int
    public_base_url: str
    admin_api_key: str | None
    canary_webhook_secret: str | None
    wazuh_ingest_secret: str | None
    ai_mode: str
    ai_api_url: str | None
    ai_api_key: str | None
    ai_model: str | None
    ai_timeout_seconds: float
    canary_base_url: str
    canary_api_path: str
    canary_alert_email: str | None
    canary_webhook_url: str | None
    wazuh_auto_collect: bool
    wazuh_indexer_url: str | None
    wazuh_indexer_username: str | None
    wazuh_indexer_password: str | None
    wazuh_index_pattern: str
    wazuh_verify_ssl: bool
    wazuh_poll_seconds: float

    @classmethod
    def from_project(cls, project_dir: Path | None = None) -> "Settings":
        root = (project_dir or Path(__file__).resolve().parents[1]).resolve()
        load_env_file(root / ".env")

        ai_mode = os.getenv("AI_MODE", "template").strip().casefold()
        if ai_mode not in {"template", "api", "auto"}:
            raise ConfigurationError("AI_MODE doit valoir template, api ou auto.")

        api_port = _port("JANUS_API_PORT", 8000)
        raw_public_url = os.getenv(
            "JANUS_PUBLIC_BASE_URL", f"http://127.0.0.1:{api_port}"
        )
        public_url = validate_http_url("JANUS_PUBLIC_BASE_URL", raw_public_url)
        raw_ai_url = os.getenv("AI_API_URL", "").strip()
        raw_wazuh_url = os.getenv("WAZUH_INDEXER_URL", "").strip()

        data_dir = root / "data"
        return cls(
            project_dir=root,
            data_dir=data_dir,
            database_path=data_dir / "janus.sqlite3",
            generated_dir=data_dir / "generated",
            api_host=os.getenv("JANUS_API_HOST", "127.0.0.1").strip() or "127.0.0.1",
            api_port=api_port,
            streamlit_host=(
                os.getenv("JANUS_STREAMLIT_HOST", "127.0.0.1").strip()
                or "127.0.0.1"
            ),
            streamlit_port=_port("JANUS_STREAMLIT_PORT", 8501),
            public_base_url=public_url,
            admin_api_key=os.getenv("JANUS_ADMIN_API_KEY", "").strip() or None,
            canary_webhook_secret=(
                os.getenv("CANARY_WEBHOOK_SECRET", "").strip() or None
            ),
            wazuh_ingest_secret=os.getenv("WAZUH_INGEST_SECRET", "").strip() or None,
            ai_mode=ai_mode,
            ai_api_url=(
                validate_http_url("AI_API_URL", raw_ai_url) if raw_ai_url else None
            ),
            ai_api_key=os.getenv("AI_API_KEY", "").strip() or None,
            ai_model=os.getenv("AI_MODEL", "").strip() or None,
            ai_timeout_seconds=_positive_float("AI_TIMEOUT_SECONDS", 30),
            canary_base_url=validate_http_url(
                "CANARY_BASE_URL",
                os.getenv("CANARY_BASE_URL", "https://canarytokens.org"),
            ),
            canary_api_path=os.getenv(
                "CANARY_API_PATH", "/d3aece8093b71007b5ccfedad91ebb11"
            ).strip(),
            canary_alert_email=os.getenv("CANARY_ALERT_EMAIL", "").strip() or None,
            canary_webhook_url=(
                validate_http_url(
                    "CANARY_WEBHOOK_URL",
                    os.getenv("CANARY_WEBHOOK_URL", ""),
                    allow_empty=True,
                )
                or None
            ),
            wazuh_auto_collect=_boolean("WAZUH_AUTO_COLLECT", False),
            wazuh_indexer_url=(
                validate_http_url("WAZUH_INDEXER_URL", raw_wazuh_url)
                if raw_wazuh_url
                else None
            ),
            wazuh_indexer_username=(
                os.getenv("WAZUH_INDEXER_USERNAME", "").strip() or None
            ),
            wazuh_indexer_password=(
                os.getenv("WAZUH_INDEXER_PASSWORD", "").strip() or None
            ),
            wazuh_index_pattern=(
                os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-4.x-*").strip()
                or "wazuh-alerts-4.x-*"
            ),
            wazuh_verify_ssl=_boolean("WAZUH_VERIFY_SSL", True),
            wazuh_poll_seconds=_positive_float("WAZUH_POLL_SECONDS", 10),
        )

    @property
    def api_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_api_url and self.ai_api_key and self.ai_model)

    @property
    def canary_official_configured(self) -> bool:
        return bool(self.canary_alert_email or self.canary_webhook_url)

    @property
    def wazuh_indexer_configured(self) -> bool:
        return bool(
            self.wazuh_indexer_url
            and self.wazuh_indexer_username
            and self.wazuh_indexer_password
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.generated_dir.mkdir(parents=True, exist_ok=True)

