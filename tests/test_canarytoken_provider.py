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
    monkeypatch.setattr(settings, "CANARYTOKEN_FAIL_CLOSED", True)
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


def test_remote_token_revocation_uses_management_credential(
    configured_provider,
    monkeypatch,
):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse({"message": "success"})

    monkeypatch.setattr(handler.requests, "post", fake_post)
    handler.delete_remote_token("token-to-retire", "management-secret")

    assert captured["url"].endswith(
        "/d3aece8093b71007b5ccfedad91ebb11/delete"
    )
    assert captured["json"] == {
        "token": "token-to-retire",
        "auth": "management-secret",
    }


def test_remote_token_revocation_requires_management_credential(
    configured_provider,
):
    with pytest.raises(handler.CanarytokenProviderError, match="gestion"):
        handler.delete_remote_token("token-to-retire", "")


def test_create_token_falls_back_locally_when_not_configured(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_EMAIL", "")
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_FAIL_CLOSED", False)
    token = handler.create_token("offline")

    assert token["provider"] == "local"
    assert token["token_type"] == "web"
    assert token["activation_mode"] == "local_development"
    assert "/ping/" in token["token_url"]


def test_excel_token_preserves_requested_type_on_local_fallback(
    configured_provider,
    monkeypatch,
):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_EMAIL", "")
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_FAIL_CLOSED", False)
    token = handler.create_token("xlsx offline", token_type="ms_excel")

    assert token["provider"] == "local"
    assert token["token_type"] == "ms_excel"
    assert token["activation_mode"] == "local_development"


def test_unconfigured_provider_fails_closed(configured_provider, monkeypatch):
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_EMAIL", "")
    monkeypatch.setattr(configured_provider, "CANARYTOKEN_FAIL_CLOSED", True)

    with pytest.raises(handler.CanarytokenProviderError, match="fail-closed"):
        handler.create_token("must have an official provider")


def test_configured_provider_failure_fails_closed(configured_provider, monkeypatch):
    def reject(*args, **kwargs):
        raise handler.CanarytokenProviderError("provider unavailable")

    monkeypatch.setattr(handler, "create_remote_token", reject)

    with pytest.raises(handler.CanarytokenProviderError, match="provider unavailable"):
        handler.create_token("must not silently fall back")


def test_local_fallback_requires_explicit_configuration(configured_provider, monkeypatch):
    def reject(*args, **kwargs):
        raise handler.CanarytokenProviderError("provider unavailable")

    monkeypatch.setattr(configured_provider, "CANARYTOKEN_FAIL_CLOSED", False)
    monkeypatch.setattr(handler, "create_remote_token", reject)
    token = handler.create_token("explicit fallback")

    assert token["provider"] == "local"
    assert token["activation_mode"] == "local_fallback_explicit"


def test_token_policy_matches_artifact_format():
    assert handler.token_policy_for_format("docx")["token_type"] == "ms_word"
    assert handler.token_policy_for_format("xlsx")["token_type"] == "ms_excel"
    assert handler.token_policy_for_format("env") == {
        "format": "env",
        "token_type": "web",
        "trigger": "url_breadcrumb_user_action_required",
        "automatic_candidate": False,
    }


def test_cloud_credentials_override_file_format_with_aws_keys():
    assert handler.token_policy_for_decoy("cloud_credentials", "env") == {
        "format": "env",
        "token_type": "aws_keys",
        "trigger": "aws_api_key_used",
        "automatic_candidate": False,
    }
    assert handler.token_policy_for_decoy("technical_config", "env")[
        "token_type"
    ] == "web"


def test_remote_aws_keys_contract(configured_provider, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse(
            {
                "token": "tok_aws_001",
                "token_url": "https://canarytokens.org/about/tok_aws_001",
                "auth_token": "auth-management-key",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "example-secret-with-forty-characters-0000",
                "region": "us-east-1",
            }
        )

    monkeypatch.setattr(handler.requests, "post", fake_post)
    token = handler.create_remote_token("AWS contract", token_type="aws_keys")

    assert captured["json"]["token_type"] == "aws_keys"
    assert token["activation_mode"] == "aws_api_usage_email"
    assert token["credential_material"] == {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "example-secret-with-forty-characters-0000",
        "aws_region": "us-east-1",
    }


def test_incomplete_aws_key_response_is_rejected(configured_provider, monkeypatch):
    monkeypatch.setattr(
        handler.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "token": "tok_aws_bad",
                "token_url": "https://canarytokens.org/about/tok_aws_bad",
                "auth_token": "auth-management-key",
            }
        ),
    )

    with pytest.raises(handler.CanarytokenProviderError, match="clés AWS"):
        handler.create_remote_token("AWS incomplete", token_type="aws_keys")


@pytest.mark.parametrize(
    ("output_format", "expected_api_type"),
    (("docx", "ms_word"), ("xlsx", "ms_excel")),
)
def test_office_policy_uses_provider_api_enum(
    configured_provider,
    monkeypatch,
    output_format,
    expected_api_type,
):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse(
            {
                "token": "tok_office_001",
                "token_url": "https://canarytokens.org/token/office.gif",
                "auth_token": "auth-management-key",
            }
        )

    monkeypatch.setattr(handler.requests, "post", fake_post)
    policy = handler.token_policy_for_format(output_format)
    token = handler.create_remote_token(
        "JANUS Office contract test",
        token_type=policy["token_type"],
    )

    assert captured["json"]["token_type"] == expected_api_type
    assert token["token_type"] == expected_api_type


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
    assert status["failure_policy"] == "fail_closed"
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
