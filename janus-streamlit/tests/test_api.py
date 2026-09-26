from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from janus.api import create_app


def test_http_flow_generates_downloads_and_protects_wazuh(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        created = client.post(
            "/api/artifacts",
            json={"theme": "Finance", "sensor_mode": "local_pixel"},
        )
        assert created.status_code == 201
        artifact = created.json()["artifact"]
        download = client.get(artifact["download_url"])
        assert download.status_code == 200
        assert download.content.startswith(b"PK")
        demo = client.post(f"/api/events/demo/{artifact['id']}")
        assert demo.status_code == 200
        blocked = client.post("/api/events/wazuh", json={"event": "test"})
        assert blocked.status_code == 503


def test_wazuh_secret_is_required_and_verified(settings):
    protected = replace(settings, wazuh_ingest_secret="test-secret")
    app = create_app(protected)
    with TestClient(app) as client:
        wrong = client.post(
            "/api/events/wazuh",
            json={"x": 1},
            headers={"X-JANUS-Wazuh-Secret": "wrong"},
        )
        assert wrong.status_code == 401

