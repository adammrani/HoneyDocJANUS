"""Tests de la racine partagée portable du projet."""

from pathlib import Path

from src.core import config as config_module


def test_default_deployment_root_is_inside_project(monkeypatch) -> None:
    monkeypatch.delenv("JANUS_DEPLOY_ROOT", raising=False)

    settings = config_module.Settings()

    expected = Path(config_module.PROJECT_ROOT) / "data" / "shared"
    assert Path(settings.JANUS_DEPLOY_ROOT).resolve() == expected.resolve()


def test_ensure_dirs_creates_configured_shared_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "JANUS_DEPLOY_ROOT",
        str(tmp_path / "runtime" / "shared"),
    )
    settings = config_module.Settings()
    monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        settings,
        "DECOY_DROP_PATH",
        str(tmp_path / "data" / "deployed_docs"),
    )
    monkeypatch.setattr(
        settings,
        "SAMPLES_DIR",
        str(tmp_path / "samples"),
    )

    settings.ensure_dirs()

    assert Path(settings.JANUS_DEPLOY_ROOT).is_dir()


def test_wazuh_collection_is_secure_and_disabled_by_default(
    monkeypatch,
) -> None:
    for name in (
        "WAZUH_AUTO_COLLECT_ENABLED",
        "WAZUH_INDEXER_USERNAME",
        "WAZUH_INDEXER_PASSWORD",
        "WAZUH_VERIFY_SSL",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = config_module.Settings()

    assert settings.WAZUH_AUTO_COLLECT_ENABLED is False
    assert settings.WAZUH_VERIFY_SSL is True
    assert settings.WAZUH_INDEXER_USERNAME == ""
    assert settings.WAZUH_INDEXER_PASSWORD == ""
    assert settings.wazuh_indexer_configured is False
