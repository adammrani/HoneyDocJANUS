"""Security boundaries for administrative routes and public callbacks."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def isolated_api(tmp_path, monkeypatch):
    from src.alerting import alert_server
    from src.core import database as database_mod
    from src.janus_v2.registry.security_signal_store import SqliteSecuritySignalStore
    from src.janus_v2.registry.wazuh_detection_store import SqliteWazuhDetectionStore

    settings = alert_server._settings
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "janus.db"))
    monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "DECOY_DROP_PATH", str(tmp_path / "generated"))
    monkeypatch.setattr(settings, "JANUS_DEPLOY_ROOT", str(tmp_path / "shared"))
    monkeypatch.setattr(settings, "SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setattr(settings, "WAZUH_AUTO_COLLECT_ENABLED", False)
    monkeypatch.setattr(settings, "FORENSIC_TELEMETRY_ENABLED", False)
    monkeypatch.setattr(database_mod, "_settings", settings)
    monkeypatch.setattr(
        alert_server,
        "_wazuh_store",
        SqliteWazuhDetectionStore(settings.DB_PATH),
    )
    monkeypatch.setattr(
        alert_server,
        "_forensic_store",
        SqliteSecuritySignalStore(settings.DB_PATH),
    )
    settings.ensure_dirs()
    return alert_server, database_mod, settings


def test_admin_routes_require_configured_key(isolated_api, monkeypatch):
    alert_server, _, settings = isolated_api
    monkeypatch.setattr(settings, "JANUS_ADMIN_API_KEY", "unit-test-secret")

    with TestClient(alert_server.app) as client:
        assert client.get("/honeydocs").status_code == 401
        assert client.get(
            "/honeydocs", headers={"X-JANUS-API-Key": "wrong"}
        ).status_code == 401
        assert client.get(
            "/honeydocs", headers={"X-JANUS-API-Key": "unit-test-secret"}
        ).status_code == 200


def test_local_development_remains_available_without_key(isolated_api, monkeypatch):
    alert_server, _, settings = isolated_api
    monkeypatch.setattr(settings, "JANUS_ADMIN_API_KEY", "")
    monkeypatch.setattr(settings, "JANUS_ALLOW_UNAUTHENTICATED_LOCAL", True)

    with TestClient(alert_server.app) as client:
        assert client.get("/honeydocs").status_code == 200


def test_unknown_callbacks_are_rejected(isolated_api, monkeypatch):
    alert_server, _, settings = isolated_api
    monkeypatch.setattr(settings, "JANUS_ADMIN_API_KEY", "")

    with TestClient(alert_server.app) as client:
        assert client.get("/ping/not-registered").status_code == 404
        assert client.get("/ci1/not-registered").status_code == 404
        assert client.post(
            "/alert", json={"token_id": "not-registered"}
        ).status_code == 404
        assert client.post(
            "/alert",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        ).status_code == 400


def test_known_local_beacon_is_linked_to_honeydoc(isolated_api, monkeypatch):
    alert_server, database_mod, settings = isolated_api
    monkeypatch.setattr(settings, "JANUS_ADMIN_API_KEY", "")

    with TestClient(alert_server.app) as client:
        honeydoc_id = database_mod.insert_honeydoc(
            filename="decoy.env",
            filepath=str(settings.JANUS_DEPLOY_ROOT) + "\\decoy.env",
            doc_type="cloud_credentials",
            file_format="env",
        )
        database_mod.insert_token(
            honeydoc_id=honeydoc_id,
            token_id="known-token",
            token_url="http://localhost/ping/known-token",
            callback_url="http://localhost/alert",
        )

        response = client.get(
            "/ping/known-token",
            headers={"User-Agent": "curl/8.5.0"},
        )
        assert response.status_code == 200
        assert response.headers["cache-control"].startswith("no-store")
        alerts = database_mod.list_alerts()
        assert alerts[0]["honeydoc_id"] == honeydoc_id
        assert alerts[0]["token_id"] == "known-token"
