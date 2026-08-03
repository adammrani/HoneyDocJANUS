"""The strategy layer should select the new cloud lure when evidence warrants it."""

from src.strategy.orchestrator import _classify_path


def test_cloud_paths_select_cloud_credentials():
    assert _classify_path(r"C:\backup\aws\service_account_recovery.env") == (
        "cloud_credentials"
    )


def test_generic_configuration_stays_technical():
    assert _classify_path(r"C:\deploy\config\application.yaml") == (
        "technical_config"
    )
