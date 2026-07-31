"""Persistance SQLite des analyses automatiques provenant de Wazuh."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..detection.pipeline import DetectionAnalysis


WAZUH_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS wazuh_detections (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key             TEXT    NOT NULL UNIQUE,
    wazuh_document_id     TEXT,
    wazuh_event_id        TEXT    NOT NULL,
    event_record_id       TEXT,
    honeydoc_id           INTEGER,
    honeydoc_instance_id  TEXT,
    matched               INTEGER NOT NULL,
    detected              INTEGER NOT NULL,
    suppressed            INTEGER NOT NULL DEFAULT 0,
    suppression_reason    TEXT,
    observed_at           TEXT    NOT NULL,
    processed_at          TEXT    NOT NULL,
    hostname              TEXT    NOT NULL,
    username              TEXT    NOT NULL,
    object_path           TEXT    NOT NULL,
    action                TEXT    NOT NULL,
    process_name          TEXT,
    process_id            TEXT,
    access_mask           TEXT,
    agent_id              TEXT,
    verdict_level         TEXT,
    verdict_score         INTEGER,
    verdict_reasons       TEXT    NOT NULL,
    raw_alert             TEXT    NOT NULL,
    FOREIGN KEY (honeydoc_id) REFERENCES honeydocs (id)
);

CREATE INDEX IF NOT EXISTS idx_wazuh_detections_observed_at
    ON wazuh_detections (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_wazuh_detections_honeydoc
    ON wazuh_detections (honeydoc_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS janus_runtime_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _honeydoc_id(instance_id: str | None) -> int | None:
    if not instance_id or not instance_id.startswith("honeydoc-"):
        return None
    try:
        return int(instance_id.removeprefix("honeydoc-"))
    except ValueError:
        return None


class SqliteWazuhDetectionStore:
    """Stocke les événements, les verdicts et le curseur du collecteur."""

    CURSOR_KEY = "wazuh_indexer_cursor"

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path).resolve()

    def _connect(self) -> sqlite3.Connection:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(WAZUH_SCHEMA_SQL)
            connection.commit()

    @staticmethod
    def _event_key(alert: dict[str, Any], analysis: DetectionAnalysis) -> str:
        document_id = alert.get("_id")
        return str(document_id or analysis.event.event_id)

    def record(
        self,
        alert: dict[str, Any],
        analysis: DetectionAnalysis,
    ) -> bool:
        """Insère une analyse et renvoie ``False`` si elle existait déjà."""

        event = analysis.event
        decoy = analysis.decoy
        verdict = analysis.verdict
        instance_id = decoy.instance_id if decoy else None

        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO wazuh_detections (
                    event_key, wazuh_document_id, wazuh_event_id,
                    event_record_id, honeydoc_id, honeydoc_instance_id,
                    matched, detected, suppressed, suppression_reason,
                    observed_at, processed_at, hostname, username,
                    object_path, action, process_name, process_id,
                    access_mask, agent_id, verdict_level, verdict_score,
                    verdict_reasons, raw_alert
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    self._event_key(alert, analysis),
                    str(alert.get("_id") or "") or None,
                    event.event_id,
                    event.event_record_id,
                    _honeydoc_id(instance_id),
                    instance_id,
                    int(decoy is not None),
                    int(analysis.detected),
                    int(analysis.suppressed),
                    analysis.suppression_reason,
                    event.timestamp.isoformat(),
                    _now(),
                    event.hostname,
                    event.user,
                    event.path,
                    event.action.value,
                    event.process_name,
                    event.process_id,
                    event.access_mask,
                    event.agent_id,
                    verdict.level.value if verdict else None,
                    verdict.score if verdict else None,
                    json.dumps(
                        verdict.reasons if verdict else [],
                        ensure_ascii=False,
                    ),
                    json.dumps(alert, ensure_ascii=False),
                ),
            )
            connection.commit()
            return cursor.rowcount == 1

    def get_cursor(self) -> list[Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM janus_runtime_state WHERE key = ?",
                (self.CURSOR_KEY,),
            ).fetchone()
        if row is None:
            return None

        value = json.loads(str(row["value"]))
        if not isinstance(value, list) or len(value) < 2:
            return None
        return value

    def set_cursor(self, cursor: list[Any]) -> None:
        value = json.dumps(cursor, ensure_ascii=False)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO janus_runtime_state (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (self.CURSOR_KEY, value, _now()),
            )
            connection.commit()

    def list_detections(
        self,
        *,
        limit: int = 100,
        matched_only: bool = False,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        condition = "WHERE matched = 1" if matched_only else ""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM wazuh_detections
                {condition}
                ORDER BY observed_at DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["matched"] = bool(item["matched"])
            item["detected"] = bool(item["detected"])
            item["suppressed"] = bool(item["suppressed"])
            item["verdict_reasons"] = json.loads(item["verdict_reasons"])
            item["raw_alert"] = json.loads(item["raw_alert"])
            results.append(item)
        return results

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM wazuh_detections"
            ).fetchone()
        return int(row["total"])
