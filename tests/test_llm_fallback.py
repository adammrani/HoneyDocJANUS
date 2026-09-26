"""Offline generation must remain relevant to the selected scenario."""

from src.tactical import llm_engine


def test_offline_hr_fallback_is_not_financial(monkeypatch):
    monkeypatch.setattr(llm_engine._settings, "GROQ_API_KEY", "")
    content = llm_engine.generate_content(
        "Tu es un responsable des ressources humaines. Rédige un document RH."
    )
    assert "EFFECTIFS" in content
    assert "chiffre d'affaires" not in content


def test_offline_cloud_fallback_is_technical(monkeypatch):
    monkeypatch.setattr(llm_engine._settings, "GROQ_API_KEY", "")
    content = llm_engine.generate_content(
        "Tu es un ingénieur cloud DevOps. Rédige une configuration de reprise."
    )
    assert "REPRISE DES SERVICES" in content
    assert "chiffre d'affaires" not in content
