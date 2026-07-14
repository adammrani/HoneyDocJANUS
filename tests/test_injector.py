"""
tests/test_injector.py
Verify that deploy_document writes a .docx and creates DB rows.

Uses a temporary DB / drop path via monkeypatching the settings singleton so
the test never touches the real data directory.
"""

import os

import pytest

from src.core import config as config_mod


@pytest.fixture()
def isolated_settings(tmp_path, monkeypatch):
    """Point DB_PATH and DECOY_DROP_PATH at a temp dir, clearing the cache."""
    config_mod.get_settings.cache_clear()
    settings = config_mod.get_settings()
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "DECOY_DROP_PATH", str(tmp_path / "drop"))
    monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "SAMPLES_DIR", str(tmp_path / "samples"))
    os.makedirs(settings.DECOY_DROP_PATH, exist_ok=True)
    yield settings
    config_mod.get_settings.cache_clear()


def test_deploy_document_creates_file_and_db_rows(isolated_settings):
    from docx import Document

    from src.core.database import init_db, list_honeydocs, get_token_by_id
    from src.lifecycle.injector import deploy_document

    init_db()

    doc = Document()
    doc.add_paragraph("Contenu de test confidentiel.")

    result = deploy_document(
        doc=doc,
        doc_type="financial_report",
        token_id="tok_test_123",
        token_url="http://localhost:8000/ping/tok_test_123",
        callback_url="http://localhost:8000/alert",
        target_dir="",
        ttl_hours=48,
    )

    # File written
    assert os.path.exists(result["deployed_path"])
    assert result["deployed_path"].endswith(".docx")

    # DB rows created
    docs = list_honeydocs()
    assert len(docs) == 1
    assert docs[0]["doc_type"] == "financial_report"

    token = get_token_by_id("tok_test_123")
    assert token is not None
    assert token["honeydoc_id"] == result["honeydoc_id"]
