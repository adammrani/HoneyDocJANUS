import pytest

from src.detection import canarytoken_handler as handler


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


@pytest.fixture()
def configured_provider(monkeypatch):
    settings = handler._settings
    monkeypatch.setattr(settings, "CANARYTOKEN_SERVER", "https://canarytokens.org")
    monkeypatch.setattr(
        settings,
        "CANARYTOKEN_API_PATH",
        "/d3aece8093b71007b5ccfedad91ebb11",
    )
    monkeypatch.setattr(settings, "CANARYTOKEN_EMAIL", "alerts@example.net")
    monkeypatch.setattr(settings, "CANARYTOKEN_TIMEOUT_SECONDS", 7.0)
    monkeypatch.setattr(settings, "CANARYTOKEN_WEBHOOK_ENABLED", False)
    monkeypatch.setattr(settings, "CALLBACK_BASE_URL", "http://localhost:8000")
    return settings


def test_remote_provider_uses_current_json_api(configured_provider, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse(
            {
                "token": "tok_remote_001",
                "token_url": "https://canarytokens.org/tags/token/contact.php",
                "auth_token": "auth-management-key",
            }
        )

    monkeypatch.setattr(handler.requests, "post", fake_post)
    token = handler.create_remote_token("JANUS test")

    assert captured["url"].endswith(
        "/d3aece8093b71007b5ccfedad91ebb11/generate"
    )
    assert captured["json"]["token_type"] == "web"
    assert captured["json"]["email"] == "alerts@example.net"
    assert "webhook_url" not in captured["json"]
    assert captured["timeout"] == 7.0
    assert token["auth_token"] == "auth-management-key"
    assert token["activation_mode"] == "automatic_email"


def test_remote_provider_adds_webhook_only_when_enabled(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_WEBHOOK_ENABLED", True)
    monkeypatch.setattr(
        configured_provider,
        "CALLBACK_BASE_URL",
        "https://janus.example.net",
    )
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse(
            {
                "token": "tok_remote_002",
                "token_url": "https://canarytokens.org/token/url",
            }
        )

    monkeypatch.setattr(handler.requests, "post", fake_post)
    token = handler.create_remote_token("JANUS webhook test")

    assert captured["json"]["webhook_url"] == "https://janus.example.net/alert"
    assert token["activation_mode"] == "automatic_email_webhook"


def test_create_token_falls_back_locally_when_not_configured(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_EMAIL", "")
    token = handler.create_token("offline")

    assert token["provider"] == "local"
    assert token["token_type"] == "web"
    assert token["activation_mode"] == "local_fallback"
    assert "/ping/" in token["token_url"]


def test_excel_token_preserves_requested_type_on_local_fallback(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_EMAIL", "")
    token = handler.create_token("xlsx offline", token_type="msexcel")

    assert token["provider"] == "local"
    assert token["token_type"] == "msexcel"
    assert token["activation_mode"] == "local_fallback"


def test_incomplete_provider_response_is_rejected(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(
        handler.requests,
        "post",
        lambda *args, **kwargs: FakeResponse({"message": "invalid request"}),
    )

    with pytest.raises(handler.CanarytokenProviderError, match="invalid request"):
        handler.create_remote_token("bad response")


def test_status_never_exposes_email(configured_provider):
    status = handler.get_canary_status()

    assert status["configured"] is True
    assert status["notification"] == "email"
    assert "email" not in status


def test_user_agent_os_is_explicitly_low_confidence():
    result = handler.guess_os_and_tool(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124"
    )

    assert "Windows" in result["os_guess"]
    assert result["os_evidence_source"] == "http_user_agent_claim"
    assert result["os_confidence"] == "low"
    assert result["os_scope"] == "requesting_client"


def test_absent_os_claim_remains_unknown():
    result = handler.guess_os_and_tool("curl/8.5.0")

    assert result["os_guess"] == "Inconnu"
    assert result["os_evidence_source"] == "none"
    assert result["os_confidence"] == "none"
    assert result["is_automated"] is True


def test_parse_callback_propagates_os_evidence_metadata():
    result = handler.parse_callback(
        {
            "token_id": "tok-1",
            "src_ip": "203.0.113.8",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
        }
    )

    assert result["os_guess"] == "Linux"
    assert result["os_confidence"] == "low"
    assert result["os_evidence_source"] == "http_user_agent_claim"
