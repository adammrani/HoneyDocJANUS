from __future__ import annotations

import json
from dataclasses import replace

from janus.ai import ContentGenerator


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, payload):
        self.payload = payload

    def post(self, *_args, **_kwargs):
        return FakeResponse(self.payload)


def test_template_mode_is_explicit(settings):
    content = ContentGenerator(settings).generate("finance", "docx")
    assert content.body
    assert content.generator_mode.startswith("local-template:")
    assert "canarytoken" not in content.body.casefold()


def test_openai_compatible_mode_is_labeled(settings):
    configured = replace(
        settings,
        ai_mode="api",
        ai_api_url="https://ai.example/v1/chat/completions",
        ai_api_key="test-key",
        ai_model="test-model",
    )
    answer = json.dumps(
        {
            "title": "Budget de travail 2027",
            "body": "Synthèse:\n" + ("Contenu professionnel synthétique et cohérent. " * 8),
        }
    )
    generated = ContentGenerator(
        configured,
        session=FakeSession({"choices": [{"message": {"content": answer}}]}),
    ).generate("finance", "docx")
    assert generated.generator_mode == "ai-api"
    assert generated.title == "Budget de travail 2027"


def test_auto_mode_fallback_never_claims_api(settings):
    automatic = replace(settings, ai_mode="auto")
    generated = ContentGenerator(automatic).generate("infrastructure", "docx")
    assert generated.generator_mode.startswith("local-template:docx:fallback-")

