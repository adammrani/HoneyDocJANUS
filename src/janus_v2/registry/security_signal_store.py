"""Persistance SQLite des observations forensiques normalisées."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..domain.signals import SecuritySignal


SIGNAL_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS security_signals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    signal_key      TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    ingested_at     TEXT NOT NULL,
    source          TEXT NOT NULL,
    platform        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    action          TEXT NOT NULL,
    agent_id        TEXT,
    hostname        TEXT,
    user_name       TEXT,
    logon_id        TEXT,
    entry_channel   TEXT,
    source_ip       TEXT,
    process_name    TEXT,
    command_line    TEXT,
    file_path       TEXT,
    payload_json    TEXT NOT NULL,
    raw_alert       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_signals_time
    ON security_signals (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_signals_kind
    ON security_signals (kind, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_signals_host
    ON security_signals (hostname, observed_at DESC);
CREATE TABLE IF NOT EXISTS janus_runtime_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteSecuritySignalStore:
    """Stocke les preuves brutes et normalisées sans les surinterpréter."""

    CURSOR_KEY = "forensic_indexer_cursor"

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path).resolve()

    def _connect(self) -> sqlite3.Connection:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(SIGNAL_SCHEMA_SQL)
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(security_signals)"
                ).fetchall()
            }
            for name in ("logon_id", "entry_channel"):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE security_signals ADD COLUMN {name} TEXT"
                    )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_signals_logon
                ON security_signals (logon_id, observed_at ASC)
                """
            )
            connection.commit()

    @staticmethod
    def _signal_key(alert: dict[str, Any], signal: SecuritySignal) -> str:
        document_id = str(alert.get("_id") or "").strip()
        return f"{signal.source}:{document_id or signal.signal_id}"

    def record(self, alert: dict[str, Any], signal: SecuritySignal) -> bool:
        """Insère un signal et renvoie ``False`` s'il était déjà présent."""

        payload = signal.to_dict()
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO security_signals (
                    signal_key, kind, observed_at, ingested_at, source,
                    platform, confidence, action, agent_id, hostname,
                    user_name, logon_id, entry_channel, source_ip,
                    process_name, command_line,
                    file_path, payload_json, raw_alert
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._signal_key(alert, signal),
                    signal.kind.value,
                    signal.observed_at.isoformat(),
                    _now(),
                    signal.source,
                    signal.platform,
                    signal.confidence.value,
                    signal.action.value,
                    signal.agent_id,
                    signal.hostname,
                    signal.user,
                    signal.logon_id,
                    signal.entry_channel,
                    signal.source_ip,
                    signal.process_name,
                    signal.command_line,
                    signal.file_path,
                    json.dumps(payload, ensure_ascii=False),
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
        return value if isinstance(value, list) and len(value) >= 2 else None

    def set_cursor(self, cursor: list[Any]) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO janus_runtime_state (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (self.CURSOR_KEY, json.dumps(cursor), _now()),
            )
            connection.commit()

    def list_signals(
        self,
        *,
        limit: int = 100,
        kind: str | None = None,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            arguments.append(kind)
        if platform:
            clauses.append("platform = ?")
            arguments.append(platform)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(int(limit), 1000)))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT id, ingested_at, payload_json
                FROM security_signals
                {where}
                ORDER BY observed_at DESC, id DESC
                LIMIT ?
                """,
                arguments,
            ).fetchall()
        results = []
        for row in rows:
            value = json.loads(row["payload_json"])
            value["database_id"] = row["id"]
            value["ingested_at"] = row["ingested_at"]
            results.append(value)
        return results

    def list_timeline(
        self,
        *,
        logon_id: str,
        hostname: str,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Retourne chronologiquement les preuves partageant un Logon ID."""

        clauses = ["logon_id = ?"]
        arguments: list[Any] = [logon_id]
        clauses.append("hostname = ?")
        arguments.append(hostname)
        arguments.append(max(1, min(int(limit), 2000)))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT id, ingested_at, payload_json
                FROM security_signals
                WHERE {' AND '.join(clauses)}
                ORDER BY observed_at ASC, id ASC
                LIMIT ?
                """,
                arguments,
            ).fetchall()
        results = []
        for row in rows:
            value = json.loads(row["payload_json"])
            value["database_id"] = row["id"]
            value["ingested_at"] = row["ingested_at"]
            results.append(value)
        return results

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM security_signals"
            ).fetchone()
        return int(row["total"])
