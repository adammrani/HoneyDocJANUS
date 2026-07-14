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


class Settings:
    """Runtime configuration, populated from environment variables."""

    def __init__(self) -> None:
        # ── Groq LLM ──────────────────────────────
        self.GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
        self.GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

        # ── Canarytokens ──────────────────────────
        self.CANARYTOKEN_SERVER: str = os.getenv(
            "CANARYTOKEN_SERVER", "https://canarytokens.org"
        )
        self.CANARYTOKEN_EMAIL: str = os.getenv(
            "CANARYTOKEN_EMAIL", "alerts@example.com"
        )

        # ── Network / callback ────────────────────
        self.CALLBACK_BASE_URL: str = os.getenv(
            "CALLBACK_BASE_URL", "http://localhost:8000"
        ).rstrip("/")
        self.API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
        self.API_PORT: int = int(os.getenv("API_PORT", "8000"))

        # ── Storage (always resolved to absolute paths) ──
        self.DB_PATH: str = _abs(os.getenv("DB_PATH", "data/honeydocs.db"))
        self.DECOY_DROP_PATH: str = _abs(
            os.getenv("DECOY_DROP_PATH", "data/deployed_docs")
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
        for path in (self.DATA_DIR, self.DECOY_DROP_PATH, self.SAMPLES_DIR):
            os.makedirs(path, exist_ok=True)

    @property
    def canarytoken_configured(self) -> bool:
        """True when a real Canarytokens email is set (enables live tokens)."""
        return bool(self.CANARYTOKEN_EMAIL) and "example.com" not in self.CANARYTOKEN_EMAIL

    @property
    def groq_configured(self) -> bool:
        """True when a Groq API key looks present (enables live generation)."""
        return self.GROQ_API_KEY.startswith("gsk_")


@lru_cache()
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance."""
    return Settings()
