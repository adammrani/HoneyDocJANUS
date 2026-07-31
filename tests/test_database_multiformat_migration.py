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
    assert {"file_format", "scenario", "sha256", "generator_version"} <= columns
    assert {
        "provider",
        "token_type",
        "auth_token",
        "activation_mode",
    } <= token_columns
