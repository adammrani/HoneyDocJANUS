from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from janus.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    base = Settings.from_project(Path(__file__).resolve().parents[1])
    data = tmp_path / "data"
    return replace(
        base,
        project_dir=tmp_path,
        data_dir=data,
        database_path=data / "janus.sqlite3",
        generated_dir=data / "generated",
        public_base_url="http://janus.test:8000",
        admin_api_key=None,
        canary_webhook_secret=None,
        wazuh_ingest_secret=None,
        ai_mode="template",
        ai_api_url=None,
        ai_api_key=None,
        ai_model=None,
        canary_alert_email=None,
        canary_webhook_url=None,
        wazuh_auto_collect=False,
        wazuh_indexer_url=None,
        wazuh_indexer_username=None,
        wazuh_indexer_password=None,
    )

