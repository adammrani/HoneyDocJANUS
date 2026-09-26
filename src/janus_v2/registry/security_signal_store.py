"""Persistance SQLite des observations forensiques normalisées."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.core.evidence import canonical_json, payload_sha256

from ..domain.signals import SecuritySignal
from .sqlite_runtime import (
    COLLECTOR_WRITE_LOCK,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_TIMEOUT_SECONDS,
)


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
    raw_alert       TEXT NOT NULL,
    raw_alert_sha256 TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_security_signals_time
    ON security_signals (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_signals_kind
    ON security_signals (kind, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_signals_host
    ON security_signals (hostname, observed_at DESC);
CREATE TABLE IF NOT EXISTS raw_evidence (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_key         TEXT NOT NULL UNIQUE,
    source               TEXT NOT NULL,
    received_at          TEXT NOT NULL,
    raw_payload_sha256   TEXT NOT NULL,
    raw_payload          TEXT NOT NULL,
    normalization_status TEXT NOT NULL,
    normalization_error  TEXT,
    signal_key           TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_status
    ON raw_evidence (normalization_status, received_at DESC);
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
        connection = sqlite3.connect(
            self._database_path,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def initialize(self) -> None:
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
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
            if "raw_alert_sha256" not in columns:
                connection.execute(
                    "ALTER TABLE security_signals "
                    "ADD COLUMN raw_alert_sha256 TEXT NOT NULL DEFAULT ''"
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

    @staticmethod
    def _raw_evidence_key(alert: dict[str, Any]) -> str:
        source = alert.get("_source")
        source_id = source.get("id") if isinstance(source, dict) else None
        identifier = alert.get("_id") or source_id or payload_sha256(alert)
        return f"wazuh:{identifier}"

    def record_raw(
        self,
        alert: dict[str, Any],
        *,
        status: str = "received",
        error: str | None = None,
    ) -> str:
        """Preserve raw Wazuh evidence before attempting normalization."""

        evidence_key = self._raw_evidence_key(alert)
        raw_json = canonical_json(alert)
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO raw_evidence (
                    evidence_key, source, received_at, raw_payload_sha256,
                    raw_payload, normalization_status, normalization_error
                ) VALUES (?, 'wazuh_indexer', ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_key) DO UPDATE SET
                    normalization_status = excluded.normalization_status,
                    normalization_error = excluded.normalization_error
                """,
                (
                    evidence_key,
                    _now(),
                    payload_sha256(alert),
                    raw_json,
                    status,
                    error,
                ),
            )
            connection.commit()
        return evidence_key

    def update_raw_status(
        self,
        evidence_key: str,
        *,
        status: str,
        error: str | None = None,
        signal_key: str | None = None,
    ) -> None:
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE raw_evidence
                SET normalization_status = ?, normalization_error = ?,
                    signal_key = COALESCE(?, signal_key)
                WHERE evidence_key = ?
                """,
                (status, error, signal_key, evidence_key),
            )
            connection.commit()

    def record(self, alert: dict[str, Any], signal: SecuritySignal) -> bool:
        """Insère un signal et renvoie ``False`` s'il était déjà présent."""

        payload = signal.to_dict()
        evidence_key = self.record_raw(alert)
        signal_key = self._signal_key(alert, signal)
        raw_json = canonical_json(alert)
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO security_signals (
                    signal_key, kind, observed_at, ingested_at, source,
                    platform, confidence, action, agent_id, hostname,
                    user_name, logon_id, entry_channel, source_ip,
                    process_name, command_line,
                    file_path, payload_json, raw_alert, raw_alert_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signal_key,
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
                    raw_json,
                    payload_sha256(alert),
                ),
            )
            connection.commit()
            inserted = cursor.rowcount == 1
        self.update_raw_status(
            evidence_key,
            status="normalized",
            signal_key=signal_key,
        )
        return inserted

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
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
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

    def prune_context(
        self,
        *,
        retention_days: int,
        max_context_signals: int,
        max_unlinked_raw: int,
    ) -> dict[str, int]:
        """Bound supporting telemetry while preserving HoneyDoc evidence.

        Rows referenced by a JANUS Wazuh detection, or whose normalized file
        path matches a registered HoneyDoc, are never selected for pruning.
        The Wazuh Indexer remains the authoritative source for older context.
        """

        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
        ).isoformat()
        with COLLECTOR_WRITE_LOCK, closing(self._connect()) as connection:
            # Reserve SQLite's single-writer slot before building the prune
            # set. This prevents both collector threads from repeatedly
            # overtaking a retention pass until it times out.
            connection.execute("BEGIN IMMEDIATE")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            protected: list[str] = []
            if "wazuh_detections" in tables:
                protected.append(
                    "EXISTS (SELECT 1 FROM wazuh_detections AS d "
                    "WHERE d.raw_alert_sha256 = security_signals.raw_alert_sha256 "
                    "AND d.raw_alert_sha256 <> '')"
                )
            if "honeydocs" in tables:
                protected.append(
                    "EXISTS (SELECT 1 FROM honeydocs AS h "
                    "WHERE security_signals.file_path IS NOT NULL "
                    "AND lower(replace(h.filepath, '/', char(92))) = "
                    "lower(replace(security_signals.file_path, '/', char(92))))"
                )
            unprotected = (
                f"NOT ({' OR '.join(protected)})" if protected else "1 = 1"
            )

            connection.execute(
                "CREATE TEMP TABLE IF NOT EXISTS janus_prune_signals "
                "(signal_key TEXT PRIMARY KEY)"
            )
            connection.execute("DELETE FROM janus_prune_signals")
            connection.execute(
                f"""
                INSERT OR IGNORE INTO janus_prune_signals(signal_key)
                SELECT signal_key
                FROM security_signals
                WHERE observed_at < ? AND {unprotected}
                """,
                (cutoff,),
            )
            connection.execute(
                f"""
                INSERT OR IGNORE INTO janus_prune_signals(signal_key)
                SELECT signal_key
                FROM security_signals
                WHERE {unprotected}
                ORDER BY observed_at DESC, id DESC
                LIMIT -1 OFFSET ?
                """,
                (max(1, int(max_context_signals)),),
            )
            selected_signals = int(
                connection.execute(
                    "SELECT COUNT(*) FROM janus_prune_signals"
                ).fetchone()[0]
            )
            deleted_raw_with_signals = connection.execute(
                "DELETE FROM raw_evidence WHERE signal_key IN "
                "(SELECT signal_key FROM janus_prune_signals)"
            ).rowcount
            deleted_signals = connection.execute(
                "DELETE FROM security_signals WHERE signal_key IN "
                "(SELECT signal_key FROM janus_prune_signals)"
            ).rowcount

            detection_guard = (
                "NOT EXISTS (SELECT 1 FROM wazuh_detections AS d "
                "WHERE d.raw_alert_sha256 = raw_evidence.raw_payload_sha256 "
                "AND d.raw_alert_sha256 <> '')"
                if "wazuh_detections" in tables
                else "1 = 1"
            )
            connection.execute(
                "CREATE TEMP TABLE IF NOT EXISTS janus_prune_raw "
                "(evidence_key TEXT PRIMARY KEY)"
            )
            connection.execute("DELETE FROM janus_prune_raw")
            connection.execute(
                f"""
                INSERT OR IGNORE INTO janus_prune_raw(evidence_key)
                SELECT evidence_key
                FROM raw_evidence
                WHERE {detection_guard}
                  AND (
                    (signal_key IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM security_signals AS s
                        WHERE s.signal_key = raw_evidence.signal_key
                    ))
                    OR (signal_key IS NULL AND received_at < ?)
                  )
                """,
                (cutoff,),
            )
            connection.execute(
                f"""
                INSERT OR IGNORE INTO janus_prune_raw(evidence_key)
                SELECT evidence_key
                FROM raw_evidence
                WHERE signal_key IS NULL AND {detection_guard}
                ORDER BY received_at DESC, id DESC
                LIMIT -1 OFFSET ?
                """,
                (max(1, int(max_unlinked_raw)),),
            )
            selected_raw = int(
                connection.execute(
                    "SELECT COUNT(*) FROM janus_prune_raw"
                ).fetchone()[0]
            )
            deleted_raw_orphans = connection.execute(
                "DELETE FROM raw_evidence WHERE evidence_key IN "
                "(SELECT evidence_key FROM janus_prune_raw)"
            ).rowcount
            connection.commit()
        deleted_raw = int(deleted_raw_with_signals) + int(deleted_raw_orphans)
        return {
            "selected_signals": selected_signals,
            "deleted_signals": int(deleted_signals),
            "selected_raw": int(deleted_raw_with_signals) + selected_raw,
            "deleted_raw": deleted_raw,
        }

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

    def list_raw_evidence(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = "WHERE normalization_status = ?" if status else ""
        arguments: list[Any] = [status] if status else []
        arguments.append(max(1, min(int(limit), 1000)))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM raw_evidence
                {clauses}
                ORDER BY received_at DESC, id DESC
                LIMIT ?
                """,
                arguments,
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["raw_payload"] = json.loads(item["raw_payload"])
            results.append(item)
        return results

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM security_signals"
            ).fetchone()
        return int(row["total"])
