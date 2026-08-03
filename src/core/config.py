"""
src/core/config.py
Centralised configuration loader.

Reads environment variables from a local `.env` file (via python-dotenv) and
exposes them through a cached `Settings` object. Every other module should call
`get_settings()` instead of reading `os.environ` directly.
"""

import os
from functools import lru_cache

from dotenv import load_dotenv

# Load .env once at import time. Missing file is fine: defaults are used.
load_dotenv()

# Project root = two levels above this file (src/core/config.py -> project/).
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _abs(path: str) -> str:
    """Resolve a possibly-relative path against the project root."""
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    """Lit une liste séparée par des virgules en supprimant les valeurs vides."""

    return tuple(
        item.strip()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    )


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} doit être un entier, reçu : {raw!r}.") from error
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} doit être compris entre {minimum} et {maximum}, reçu : {value}."
        )
    return value


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as error:
        raise ValueError(f"{name} doit être un nombre, reçu : {raw!r}.") from error
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} doit être compris entre {minimum} et {maximum}, reçu : {value}."
        )
    return value


class Settings:
    """Runtime configuration, populated from environment variables."""

    def __init__(self) -> None:
        # ── Groq LLM ──────────────────────────────
        self.GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
        self.GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

        # ── Canarytokens ──────────────────────────
        self.CANARYTOKEN_SERVER: str = os.getenv(
            "CANARYTOKEN_SERVER", "https://canarytokens.org"
        ).rstrip("/")
        self.CANARYTOKEN_API_PATH: str = os.getenv(
            "CANARYTOKEN_API_PATH",
            "/d3aece8093b71007b5ccfedad91ebb11",
        )
        if not self.CANARYTOKEN_API_PATH.startswith("/"):
            self.CANARYTOKEN_API_PATH = f"/{self.CANARYTOKEN_API_PATH}"
        self.CANARYTOKEN_EMAIL: str = os.getenv(
            "CANARYTOKEN_EMAIL", "alerts@example.com"
        )
        self.CANARYTOKEN_TIMEOUT_SECONDS: float = _env_float(
            "CANARYTOKEN_TIMEOUT_SECONDS", 10, 0.1, 300
        )
        self.CANARYTOKEN_WEBHOOK_ENABLED: bool = _env_bool(
            "CANARYTOKEN_WEBHOOK_ENABLED",
            False,
        )

        # ── Network / callback ────────────────────
        self.CALLBACK_BASE_URL: str = os.getenv(
            "CALLBACK_BASE_URL", "http://localhost:8000"
        ).rstrip("/")
        self.API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
        self.API_PORT: int = _env_int("API_PORT", 8000, 1, 65535)
        self.JANUS_ADMIN_API_KEY: str = os.getenv(
            "JANUS_ADMIN_API_KEY", ""
        ).strip()
        self.JANUS_ALLOW_UNAUTHENTICATED_LOCAL: bool = _env_bool(
            "JANUS_ALLOW_UNAUTHENTICATED_LOCAL", True
        )
        self.ROTATION_INTERVAL_MINUTES: int = _env_int(
            "ROTATION_INTERVAL_MINUTES", 30, 1, 10080
        )
        self.DECOY_INFRA_ENABLED: bool = _env_bool("DECOY_INFRA_ENABLED", True)
        self.DECOY_BIND_HOST: str = os.getenv("DECOY_BIND_HOST", "127.0.0.1")
        self.DECOY_HTTP_PORT: int = _env_int("DECOY_HTTP_PORT", 8080, 1, 65535)
        self.DECOY_SSH_PORT: int = _env_int("DECOY_SSH_PORT", 2222, 1, 65535)

        # ── Storage (always resolved to absolute paths) ──
        self.DB_PATH: str = _abs(os.getenv("DB_PATH", "data/honeydocs.db"))
        self.DECOY_DROP_PATH: str = _abs(
            os.getenv("DECOY_DROP_PATH", "data/deployed_docs")
        )
        self.JANUS_DEPLOY_ROOT: str = _abs(
            os.getenv("JANUS_DEPLOY_ROOT", "data/shared")
        )

        # ── Wazuh Indexer automatic collection ──
        self.WAZUH_AUTO_COLLECT_ENABLED: bool = _env_bool(
            "WAZUH_AUTO_COLLECT_ENABLED",
            False,
        )
        self.WAZUH_INDEXER_URL: str = os.getenv(
            "WAZUH_INDEXER_URL",
            "https://localhost:9200",
        ).rstrip("/")
        self.WAZUH_INDEXER_USERNAME: str = os.getenv(
            "WAZUH_INDEXER_USERNAME",
            "",
        )
        self.WAZUH_INDEXER_PASSWORD: str = os.getenv(
            "WAZUH_INDEXER_PASSWORD",
            "",
        )
        self.WAZUH_INDEX_PATTERN: str = os.getenv(
            "WAZUH_INDEX_PATTERN",
            "wazuh-alerts-4.x-*",
        )
        self.WAZUH_RULE_ID: str = os.getenv("WAZUH_RULE_ID", "100100")
        self.WAZUH_ADDITIONAL_RULE_IDS: tuple[str, ...] = _env_csv(
            "WAZUH_ADDITIONAL_RULE_IDS", "100101,100102,100103,100104"
        )
        self.WAZUH_VERIFY_SSL: bool = _env_bool("WAZUH_VERIFY_SSL", True)
        wazuh_ca_cert = os.getenv("WAZUH_CA_CERT_PATH", "").strip()
        self.WAZUH_CA_CERT_PATH: str = (
            _abs(wazuh_ca_cert) if wazuh_ca_cert else ""
        )
        self.WAZUH_POLL_INTERVAL_SECONDS: float = _env_float(
            "WAZUH_POLL_INTERVAL_SECONDS", 5, 0.1, 3600
        )
        self.WAZUH_INITIAL_LOOKBACK_MINUTES: int = _env_int(
            "WAZUH_INITIAL_LOOKBACK_MINUTES", 15, 0, 10080
        )
        self.WAZUH_OVERLAP_SECONDS: int = _env_int(
            "WAZUH_OVERLAP_SECONDS", 120, 0, 3600
        )
        self.WAZUH_EVENT_SETTLE_SECONDS: int = _env_int(
            "WAZUH_EVENT_SETTLE_SECONDS", 3, 0, 300
        )
        self.WAZUH_BATCH_SIZE: int = _env_int(
            "WAZUH_BATCH_SIZE", 200, 1, 10000
        )
        self.WAZUH_REQUEST_TIMEOUT_SECONDS: float = _env_float(
            "WAZUH_REQUEST_TIMEOUT_SECONDS", 10, 0.1, 300
        )
        self.WAZUH_DEPLOYMENT_GRACE_SECONDS: float = _env_float(
            "WAZUH_DEPLOYMENT_GRACE_SECONDS", 15, 0, 3600
        )

        # ── Télémétrie forensique Windows, Sysmon et Linux auditd ──
        self.FORENSIC_TELEMETRY_ENABLED: bool = _env_bool(
            "FORENSIC_TELEMETRY_ENABLED", False
        )
        self.FORENSIC_WINDOWS_EVENT_IDS: tuple[str, ...] = _env_csv(
            "FORENSIC_WINDOWS_EVENT_IDS",
            "4624,4663,4688,5145,1,3,11,22,23,26",
        )
        self.FORENSIC_AUDIT_KEYS: tuple[str, ...] = _env_csv(
            "FORENSIC_AUDIT_KEYS", "audit-wazuh-c,janus-command"
        )
        self.FORENSIC_AGENT_IDS: tuple[str, ...] = _env_csv(
            "FORENSIC_AGENT_IDS", ""
        )
        self.FORENSIC_LOGON_TYPES: tuple[str, ...] = _env_csv(
            "FORENSIC_LOGON_TYPES", "2,3,8,9,10,11,12,13"
        )

        # ── Derived / static paths ────────────────
        self.PROJECT_ROOT: str = PROJECT_ROOT
        self.CONFIG_DIR: str = os.path.join(PROJECT_ROOT, "config")
        self.CORPUS_DIR: str = os.path.join(PROJECT_ROOT, "corpus")
        self.DATA_DIR: str = os.path.join(PROJECT_ROOT, "data")
        self.SAMPLES_DIR: str = os.path.join(PROJECT_ROOT, "scenarios", "samples")
        self.LOG_FILE: str = os.path.join(self.DATA_DIR, "honeydocs.log")

    def ensure_dirs(self) -> None:
        """Create data directories at startup if they do not exist."""
        for path in (
            self.DATA_DIR,
            self.DECOY_DROP_PATH,
            self.JANUS_DEPLOY_ROOT,
            self.SAMPLES_DIR,
        ):
            os.makedirs(path, exist_ok=True)

    @property
    def canarytoken_configured(self) -> bool:
        """True when a real Canarytokens email is set (enables live tokens)."""
        return bool(self.CANARYTOKEN_EMAIL) and "example.com" not in self.CANARYTOKEN_EMAIL

    @property
    def groq_configured(self) -> bool:
        """True when a Groq API key looks present (enables live generation)."""
        return self.GROQ_API_KEY.startswith("gsk_")

    @property
    def wazuh_indexer_configured(self) -> bool:
        """True lorsque la collecte est activée avec des identifiants."""

        return bool(
            self.WAZUH_AUTO_COLLECT_ENABLED
            and self.WAZUH_INDEXER_URL
            and self.WAZUH_INDEXER_USERNAME
            and self.WAZUH_INDEXER_PASSWORD
        )

    @property
    def forensic_telemetry_configured(self) -> bool:
        """True quand la collecte forensique peut joindre l'Indexer."""

        return bool(
            self.FORENSIC_TELEMETRY_ENABLED
            and self.WAZUH_INDEXER_URL
            and self.WAZUH_INDEXER_USERNAME
            and self.WAZUH_INDEXER_PASSWORD
            and (self.FORENSIC_WINDOWS_EVENT_IDS or self.FORENSIC_AUDIT_KEYS)
        )


@lru_cache()
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance."""
    return Settings()
