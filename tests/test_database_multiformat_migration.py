import sqlite3


def test_init_db_migrates_existing_honeydocs_table(tmp_path, monkeypatch):
    from src.core import config as config_mod
    from src.core import database as database_mod

    database_path = tmp_path / "legacy.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE honeydocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                target_dir TEXT,
                created_at TEXT NOT NULL,
                ttl_hours INTEGER NOT NULL DEFAULT 72,
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )

    config_mod.get_settings.cache_clear()
    settings = config_mod.get_settings()
    monkeypatch.setattr(settings, "DB_PATH", str(database_path))
    monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "DECOY_DROP_PATH", str(tmp_path / "drop"))
    monkeypatch.setattr(settings, "JANUS_DEPLOY_ROOT", str(tmp_path / "shared"))
    monkeypatch.setattr(settings, "SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setattr(database_mod, "_settings", settings)

    database_mod.init_db()

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(honeydocs)")
        }
        token_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(tokens)")
        }
        alert_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(alerts)")
        }
        raw_evidence_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='raw_evidence'"
        ).fetchone()
    assert {
        "file_format",
        "scenario",
        "sha256",
        "generator_version",
        "retired_at",
        "retirement_reason",
    } <= columns
    assert {
        "provider",
        "token_type",
        "auth_token",
        "activation_mode",
        "revoked_at",
        "revocation_status",
        "revocation_error",
    } <= token_columns
    assert {
        "raw_payload_sha256",
        "sensor_source",
        "evidence_nature",
        "evidence_strength",
        "transport_trust",
    } <= alert_columns
    assert raw_evidence_table is not None

    honeydoc_id = database_mod.insert_honeydoc(
        filename="budget.docx",
        filepath=str(tmp_path / "budget.docx"),
        doc_type="financial_report",
        target_dir=str(tmp_path / "shared"),
        ttl_hours=72,
        file_format="docx",
    )
    database_mod.insert_token(
        honeydoc_id=honeydoc_id,
        token_id="safe-token-id",
        token_url="https://example.invalid/beacon",
        callback_url="",
        provider="canarytokens",
        token_type="ms_word",
        auth_token="must-never-be-listed",
        activation_mode="automatic_email",
    )

    listed = database_mod.list_honeydocs()[0]
    assert listed["token_provider"] == "canarytokens"
    assert listed["token_type"] == "ms_word"
    assert listed["token_activation"] == "automatic_email"
    assert listed["token_status"] == "active"
    assert "token_url" not in listed
    assert "auth_token" not in listed
