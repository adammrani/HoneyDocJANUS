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

    # Ces modules gardent l'instance de configuration créée à l'import.
    # On la remplace afin que chaque test reste strictement isolé.
    from src.core import database as database_mod
    from src.lifecycle import injector as injector_mod

    monkeypatch.setattr(database_mod, "_settings", settings)
    monkeypatch.setattr(injector_mod, "_settings", settings)

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
        token_provider="canarytokens",
        token_type="web",
        token_auth_token="auth-test-key",
        token_activation="automatic_email",
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
    assert token["provider"] == "canarytokens"
    assert token["token_type"] == "web"
    assert token["auth_token"] == "auth-test-key"
    assert token["activation_mode"] == "automatic_email"


def test_strict_deployment_records_the_live_path(isolated_settings, tmp_path):
    from docx import Document

    from src.core.database import init_db, list_honeydocs
    from src.lifecycle.injector import deploy_document

    init_db()
    live_directory = tmp_path / "shared"
    live_directory.mkdir()

    doc = Document()
    doc.add_paragraph("Honeydocument déployé dans la zone surveillée.")

    result = deploy_document(
        doc=doc,
        doc_type="financial_report",
        token_id="tok_live_123",
        token_url="http://localhost:8000/ping/tok_live_123",
        callback_url="http://localhost:8000/alert",
        target_dir=str(live_directory),
        ttl_hours=48,
        strict_target=True,
    )

    deployed_path = os.path.abspath(result["deployed_path"])
    assert os.path.dirname(deployed_path) == os.path.abspath(live_directory)
    assert os.path.exists(deployed_path)

    rows = list_honeydocs()
    assert len(rows) == 1
    assert os.path.abspath(rows[0]["filepath"]) == deployed_path


def test_strict_deployment_does_not_register_a_missing_target(
    isolated_settings,
    tmp_path,
):
    from docx import Document

    from src.core.database import init_db, list_honeydocs
    from src.lifecycle.injector import deploy_document

    init_db()
    doc = Document()

    with pytest.raises(ValueError, match="does not exist"):
        deploy_document(
            doc=doc,
            doc_type="technical_config",
            token_id="tok_invalid_123",
            token_url="http://localhost:8000/ping/tok_invalid_123",
            callback_url="http://localhost:8000/alert",
            target_dir=str(tmp_path / "missing"),
            strict_target=True,
        )

    assert list_honeydocs() == []


def test_deploy_xlsx_records_format_hash_and_scenario(isolated_settings, tmp_path):
    from src.core.database import init_db, list_honeydocs
    from src.janus.generators.accounting_workbook import build_accounting_workbook
    from src.lifecycle.injector import deploy_document

    init_db()
    live_directory = tmp_path / "shared"
    live_directory.mkdir()
    workbook = build_accounting_workbook(
        summary_text="Synthèse de test.",
        token_id="tok_xlsx_001",
        fiscal_year=2026,
    )

    result = deploy_document(
        doc=workbook,
        doc_type="financial_report",
        token_id="tok_xlsx_001",
        token_url="",
        callback_url="",
        target_dir=str(live_directory),
        strict_target=True,
        output_format="xlsx",
        scenario="financial_accounting",
        generator_version="test-generator/1.0",
    )

    assert result["filename"].endswith(".xlsx")
    assert len(result["sha256"]) == 64
    rows = list_honeydocs()
    assert rows[0]["file_format"] == "xlsx"
    assert rows[0]["scenario"] == "financial_accounting"
    assert rows[0]["sha256"] == result["sha256"]
