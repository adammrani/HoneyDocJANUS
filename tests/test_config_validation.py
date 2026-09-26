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


def test_experimental_components_are_disabled_by_default(monkeypatch):
    for name in (
        "ROTATION_ENABLED",
        "DECOY_INFRA_ENABLED",
        "EXPERIMENTAL_CI1_ENABLED",
        "EXPERIMENTAL_CREDENTIAL_TRAP_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = Settings()

    assert settings.ROTATION_ENABLED is False
    assert settings.DECOY_INFRA_ENABLED is False
    assert settings.EXPERIMENTAL_CI1_ENABLED is False
    assert settings.EXPERIMENTAL_CREDENTIAL_TRAP_ENABLED is False
    assert settings.CANARYTOKEN_FAIL_CLOSED is True
