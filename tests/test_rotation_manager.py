"""Rotation must preserve coverage and the generated format."""

from datetime import datetime, timedelta, timezone

from src.lifecycle import rotation_manager


def _expired_doc() -> dict:
    return {
        "id": 7,
        "doc_type": "cloud_credentials",
        "file_format": "zip",
        "scenario": "cloud_recovery",
        "target_dir": r"C:\JANUS\shared",
        "ttl_hours": 24,
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(),
    }


def test_rotation_regenerates_before_deactivation(monkeypatch):
    captured = {}
    deactivated = []

    class Response:
        ok = True
        status_code = 200

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(rotation_manager, "list_active_honeydocs", lambda: [_expired_doc()])
    monkeypatch.setattr(rotation_manager, "deactivate_honeydoc", deactivated.append)
    monkeypatch.setattr(rotation_manager.requests, "post", fake_post)
    monkeypatch.setattr(
        rotation_manager._settings,
        "JANUS_ADMIN_API_KEY",
        "rotation-secret",
    )

    summary = rotation_manager.check_and_rotate("http://127.0.0.1:8000")

    assert deactivated == [7]
    assert captured["json"]["output_format"] == "zip"
    assert captured["json"]["scenario"] == "cloud_recovery"
    assert captured["headers"]["X-JANUS-API-Key"] == "rotation-secret"
    assert summary == {"checked": 1, "rotated": 1, "regenerated": 1, "failed": 0}


def test_failed_regeneration_keeps_existing_decoy_active(monkeypatch):
    deactivated = []

    class Response:
        ok = False
        status_code = 503

    monkeypatch.setattr(rotation_manager, "list_active_honeydocs", lambda: [_expired_doc()])
    monkeypatch.setattr(rotation_manager, "deactivate_honeydoc", deactivated.append)
    monkeypatch.setattr(rotation_manager.requests, "post", lambda *args, **kwargs: Response())

    summary = rotation_manager.check_and_rotate("http://127.0.0.1:8000")

    assert deactivated == []
    assert summary["rotated"] == 0
    assert summary["failed"] == 1
