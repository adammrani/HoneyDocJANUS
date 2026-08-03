"""Invalid numeric environment values must fail with a clear message."""

import pytest

from src.core.config import Settings


def test_invalid_api_port_is_rejected(monkeypatch):
    monkeypatch.setenv("API_PORT", "70000")
    with pytest.raises(ValueError, match="API_PORT"):
        Settings()


def test_zero_rotation_interval_is_rejected(monkeypatch):
    monkeypatch.setenv("ROTATION_INTERVAL_MINUTES", "0")
    with pytest.raises(ValueError, match="ROTATION_INTERVAL_MINUTES"):
        Settings()
