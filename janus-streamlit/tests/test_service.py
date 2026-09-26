from __future__ import annotations

from janus.models import GenerateRequest, SensorMode, TransportTrust
from janus.service import JanusService


def test_local_generation_and_controlled_pixel(settings):
    service = JanusService(settings)
    artifact = service.generate(
        GenerateRequest(theme="Finance", sensor_mode=SensorMode.LOCAL_PIXEL)
    )
    assert artifact["has_local_pixel"] is True
    assert "local_token" not in artifact
    path, registered = service.download_path(artifact["id"])
    assert path.exists()
    assert path.stat().st_size == registered["size_bytes"]

    result = service.controlled_pixel_test(artifact["id"])
    assert result["category"] == "controlled"
    events = service.state()["events"]
    pixel = next(event for event in events if event["source"] == "janus_pixel")
    assert pixel["category"] == "controlled"
    assert pixel["transport_trust"] == "unverified"


def test_public_pixel_query_cannot_claim_controlled_status(settings):
    service = JanusService(settings)
    artifact = service.generate(
        GenerateRequest(theme="Finance", sensor_mode=SensorMode.LOCAL_PIXEL)
    )
    private_artifact = service.database.get_artifact(artifact["id"])

    assert service.record_pixel(
        private_artifact["local_token"],
        remote_ip="203.0.113.10",
        user_agent="Word/Test",
        headers={},
        query={"test": "1"},
    )
    pixel = next(
        event
        for event in service.state()["events"]
        if event["source"] == "janus_pixel"
    )
    assert pixel["category"] == "observed"
    assert pixel["is_controlled"] is False


def test_unverified_canary_does_not_become_confirmed(settings):
    service = JanusService(settings)
    artifact = service.generate(
        GenerateRequest(
            theme="Finance",
            sensor_mode=SensorMode.CANARY_REMOTE,
            canary_url="https://canary.example/abc.gif",
        )
    )
    result = service.ingest_canary(
        {"token": "abc", "src_ip": "203.0.113.9", "useragent": "Word/Test"},
        transport=TransportTrust.UNVERIFIED,
    )
    assert result["artifact_id"] == artifact["id"]
    event = service.state()["events"][0]
    assert event["strength"] == "candidate"
    assert event["transport_trust"] == "unverified"
