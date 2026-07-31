def test_generate_xlsx_pipeline_deploys_and_registers(tmp_path, monkeypatch):
    from src.alerting import alert_server
    from src.core import database as database_mod
    from src.detection import canarytoken_handler
    from src.lifecycle import injector as injector_mod
    from src.schemas.event_models import GenerateRequest

    settings = alert_server._settings
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "janus.db"))
    monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "DECOY_DROP_PATH", str(tmp_path / "generated"))
    monkeypatch.setattr(settings, "JANUS_DEPLOY_ROOT", str(tmp_path / "shared"))
    monkeypatch.setattr(settings, "SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setattr(settings, "CANARYTOKEN_EMAIL", "")

    monkeypatch.setattr(database_mod, "_settings", settings)
    monkeypatch.setattr(injector_mod, "_settings", settings)
    monkeypatch.setattr(canarytoken_handler, "_settings", settings)

    settings.ensure_dirs()
    database_mod.init_db()
    response = alert_server.generate_decoy(
        GenerateRequest(
            doc_type="financial_report",
            output_format="xlsx",
            company_name="JANUS Audit SA",
            fiscal_year=2026,
        )
    )

    assert response.file_format == "xlsx"
    assert response.scenario == "financial_accounting"
    assert response.token_activation == "local_fallback"
    assert response.token_type == "msexcel"
    assert response.detection_layers == ["wazuh_sacl", "document_beacon"]
    assert len(response.sha256) == 64
    assert (tmp_path / "shared" / response.filename).is_file()

    rows = database_mod.list_honeydocs()
    assert len(rows) == 1
    assert rows[0]["filepath"] == response.deployed_path
    assert rows[0]["file_format"] == "xlsx"
