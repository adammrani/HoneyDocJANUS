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
        "filename": "cloud_recovery_bundle.zip",
        "filepath": r"C:\JANUS\shared\cloud_recovery_bundle.zip",
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
    monkeypatch.setattr(
        rotation_manager,
        "deactivate_honeydoc",
        lambda honeydoc_id, reason: deactivated.append((honeydoc_id, reason)),
    )
    monkeypatch.setattr(
        rotation_manager,
        "_revoke_registered_token",
        lambda honeydoc_id: "revoked",
    )
    monkeypatch.setattr(rotation_manager, "_remove_retired_files", lambda doc: 2)
    monkeypatch.setattr(rotation_manager.requests, "post", fake_post)
    monkeypatch.setattr(
        rotation_manager._settings,
        "JANUS_ADMIN_API_KEY",
        "rotation-secret",
    )

    summary = rotation_manager.check_and_rotate("http://127.0.0.1:8000")

    assert deactivated == [(7, "ttl_rotation_replaced")]
    assert captured["json"]["output_format"] == "zip"
    assert captured["json"]["scenario"] == "cloud_recovery"
    assert captured["headers"]["X-JANUS-API-Key"] == "rotation-secret"
    assert summary == {
        "checked": 1,
        "rotated": 1,
        "regenerated": 1,
        "failed": 0,
        "revoked": 1,
        "revocation_failed": 0,
        "files_removed": 2,
    }


def test_failed_regeneration_keeps_existing_decoy_active(monkeypatch):
    deactivated = []

    class Response:
        ok = False
        status_code = 503

    monkeypatch.setattr(rotation_manager, "list_active_honeydocs", lambda: [_expired_doc()])
    monkeypatch.setattr(
        rotation_manager,
        "deactivate_honeydoc",
        lambda honeydoc_id, reason: deactivated.append((honeydoc_id, reason)),
    )
    monkeypatch.setattr(rotation_manager.requests, "post", lambda *args, **kwargs: Response())

    summary = rotation_manager.check_and_rotate("http://127.0.0.1:8000")

    assert deactivated == []
    assert summary["rotated"] == 0
    assert summary["failed"] == 1


def test_registered_remote_token_is_revoked_and_audited(monkeypatch):
    deleted = []
    marked = []
    monkeypatch.setattr(
        rotation_manager,
        "get_token_by_honeydoc_id",
        lambda honeydoc_id: {
            "token_id": "remote-token-001",
            "provider": "canarytokens",
            "auth_token": "management-secret",
        },
    )
    monkeypatch.setattr(
        rotation_manager,
        "delete_remote_token",
        lambda token_id, auth_token: deleted.append((token_id, auth_token)),
    )
    monkeypatch.setattr(
        rotation_manager,
        "mark_token_revocation",
        lambda token_id, **values: marked.append((token_id, values)),
    )

    status = rotation_manager._revoke_registered_token(7)

    assert status == "revoked"
    assert deleted == [("remote-token-001", "management-secret")]
    assert marked == [("remote-token-001", {"status": "revoked"})]
