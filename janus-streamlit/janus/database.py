"""Registre SQLite local : artefacts, événements bruts et vues normalisées."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    objective TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    title TEXT NOT NULL,
    theme TEXT NOT NULL,
    department TEXT NOT NULL,
    audience TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    deployment_path TEXT,
    document_format TEXT NOT NULL DEFAULT 'docx',
    sensor_mode TEXT NOT NULL,
    local_token TEXT UNIQUE,
    canary_url TEXT,
    canary_provider TEXT,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    content_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS artifact_secrets (
    artifact_id TEXT PRIMARY KEY,
    provider_token TEXT,
    provider_auth_token TEXT,
    provider_hostname TEXT,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS raw_events (
    id TEXT PRIMARY KEY,
    artifact_id TEXT,
    source TEXT NOT NULL,
    source_event_id TEXT,
    dedupe_key TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    transport_trust TEXT NOT NULL,
    UNIQUE (source, dedupe_key),
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
);

CREATE TABLE IF NOT EXISTS evidence_events (
    id TEXT PRIMARY KEY,
    raw_event_id TEXT NOT NULL,
    artifact_id TEXT,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    category TEXT NOT NULL,
    strength TEXT NOT NULL,
    transport_trust TEXT NOT NULL,
    summary TEXT NOT NULL,
    observed_at TEXT,
    received_at TEXT NOT NULL,
    remote_ip TEXT,
    user_agent TEXT,
    hostname TEXT,
    user_name TEXT,
    process_name TEXT,
    process_id TEXT,
    process_guid TEXT,
    logon_id TEXT,
    file_path TEXT,
    event_code TEXT,
    action TEXT,
    is_controlled INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL,
    FOREIGN KEY (raw_event_id) REFERENCES raw_events(id),
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
);

CREATE TABLE IF NOT EXISTS runtime_state (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_created ON artifacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifacts_path ON artifacts(deployment_path);
CREATE INDEX IF NOT EXISTS idx_raw_received ON raw_events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_artifact_time
    ON evidence_events(artifact_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_session
    ON evidence_events(hostname, logon_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_evidence_code
    ON evidence_events(event_code, received_at DESC);
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path.resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_artifact(
        self,
        *,
        campaign: dict[str, Any],
        artifact: dict[str, Any],
        secrets: dict[str, str | None] | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO campaigns (id, name, objective, created_at) VALUES (?, ?, ?, ?)",
                (
                    campaign["id"],
                    campaign["name"],
                    campaign["objective"],
                    campaign["created_at"],
                ),
            )
            connection.execute(
                """
                INSERT INTO artifacts (
                    id, campaign_id, title, theme, department, audience,
                    sensitivity, filename, file_path, deployment_path,
                    document_format, sensor_mode, local_token, canary_url,
                    canary_provider, sha256, size_bytes, content_mode, status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact["id"],
                    artifact["campaign_id"],
                    artifact["title"],
                    artifact["theme"],
                    artifact["department"],
                    artifact["audience"],
                    artifact["sensitivity"],
                    artifact["filename"],
                    artifact["file_path"],
                    artifact.get("deployment_path"),
                    artifact.get("document_format", "docx"),
                    artifact["sensor_mode"],
                    artifact.get("local_token"),
                    artifact.get("canary_url"),
                    artifact.get("canary_provider"),
                    artifact["sha256"],
                    artifact["size_bytes"],
                    artifact["content_mode"],
                    artifact.get("status", "ready"),
                    artifact["created_at"],
                ),
            )
            if secrets:
                connection.execute(
                    """
                    INSERT INTO artifact_secrets (
                        artifact_id, provider_token, provider_auth_token, provider_hostname
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        artifact["id"],
                        secrets.get("provider_token"),
                        secrets.get("provider_auth_token"),
                        secrets.get("provider_hostname"),
                    ),
                )

    @staticmethod
    def _artifact_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        value = dict(row)
        value["has_local_pixel"] = bool(value.get("local_token"))
        value["has_canary"] = bool(value.get("canary_url") or value.get("canary_provider"))
        value.pop("local_token", None)
        value.pop("canary_url", None)
        value.pop("file_path", None)
        return value

    def list_artifacts(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT a.*, c.name AS campaign_name,
                       COUNT(e.id) AS event_count,
                       MAX(e.received_at) AS last_event_at
                FROM artifacts a
                JOIN campaigns c ON c.id = a.campaign_id
                LEFT JOIN evidence_events e ON e.artifact_id = a.id
                GROUP BY a.id
                ORDER BY a.created_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [self._artifact_public(row) for row in rows]

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_artifact_public(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.get_artifact(artifact_id)
        return self._artifact_public(row) if row else None

    def get_artifact_secrets(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_secrets WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        return dict(row) if row else None

    def artifact_by_local_token(self, token: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE local_token = ?", (token,)
            ).fetchone()
        return dict(row) if row else None

    def artifact_by_canary_reference(self, reference: str) -> dict[str, Any] | None:
        if not reference:
            return None
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT a.*
                FROM artifacts a
                LEFT JOIN artifact_secrets s ON s.artifact_id = a.id
                WHERE s.provider_token = ? OR a.canary_url LIKE ?
                ORDER BY a.created_at DESC LIMIT 1
                """,
                (reference, f"%{reference}%"),
            ).fetchone()
        return dict(row) if row else None

    def find_artifact_by_exact_path(self, normalized_path: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE deployment_path IS NOT NULL"
            ).fetchall()
        for row in rows:
            candidate = str(row["deployment_path"] or "").replace("/", "\\").casefold()
            if candidate == normalized_path:
                return dict(row)
        return None

    def find_artifact_by_filename(self, filename: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE lower(filename) = lower(?) ORDER BY created_at DESC LIMIT 1",
                (filename,),
            ).fetchone()
        return dict(row) if row else None

    def insert_raw_and_evidence(
        self,
        *,
        raw: dict[str, Any],
        evidence: dict[str, Any],
    ) -> tuple[str, str, bool]:
        """Insère atomiquement le brut puis sa vue. Renvoie False si doublon source."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO raw_events (
                    id, artifact_id, source, source_event_id, dedupe_key,
                    received_at, payload_sha256, payload_json, transport_trust
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw["id"],
                    raw.get("artifact_id"),
                    raw["source"],
                    raw.get("source_event_id"),
                    raw["dedupe_key"],
                    raw["received_at"],
                    raw["payload_sha256"],
                    raw["payload_json"],
                    raw["transport_trust"],
                ),
            )
            if cursor.rowcount != 1:
                existing = connection.execute(
                    "SELECT id FROM raw_events WHERE source = ? AND dedupe_key = ?",
                    (raw["source"], raw["dedupe_key"]),
                ).fetchone()
                return str(existing["id"]), "", False

            connection.execute(
                """
                INSERT INTO evidence_events (
                    id, raw_event_id, artifact_id, source, kind, category,
                    strength, transport_trust, summary, observed_at, received_at,
                    remote_ip, user_agent, hostname, user_name, process_name,
                    process_id, process_guid, logon_id, file_path, event_code,
                    action, is_controlled, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence["id"],
                    raw["id"],
                    evidence.get("artifact_id"),
                    evidence["source"],
                    evidence["kind"],
                    evidence["category"],
                    evidence["strength"],
                    evidence["transport_trust"],
                    evidence["summary"],
                    evidence.get("observed_at"),
                    evidence["received_at"],
                    evidence.get("remote_ip"),
                    evidence.get("user_agent"),
                    evidence.get("hostname"),
                    evidence.get("user_name"),
                    evidence.get("process_name"),
                    evidence.get("process_id"),
                    evidence.get("process_guid"),
                    evidence.get("logon_id"),
                    evidence.get("file_path"),
                    evidence.get("event_code"),
                    evidence.get("action"),
                    int(bool(evidence.get("is_controlled"))),
                    json.dumps(evidence.get("details", {}), ensure_ascii=False),
                ),
            )
        return raw["id"], evidence["id"], True

    def list_evidence(
        self,
        limit: int = 300,
        *,
        artifact_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if artifact_id:
            clauses.append("e.artifact_id = ?")
            arguments.append(artifact_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(limit, 2000)))
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT e.*, a.title AS artifact_title, a.filename AS artifact_filename,
                       r.payload_sha256 AS raw_sha256
                FROM evidence_events e
                LEFT JOIN artifacts a ON a.id = e.artifact_id
                JOIN raw_events r ON r.id = e.raw_event_id
                {where}
                ORDER BY e.received_at DESC, e.id DESC
                LIMIT ?
                """,
                arguments,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["is_controlled"] = bool(item["is_controlled"])
            item["details"] = json.loads(item.pop("details_json") or "{}")
            result.append(item)
        return result

    def raw_event(self, raw_event_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM raw_events WHERE id = ?", (raw_event_id,)
            ).fetchone()
        if not row:
            return None
        value = dict(row)
        value["payload"] = json.loads(value.pop("payload_json"))
        return value

    def session_events(
        self,
        *,
        artifact_id: str,
        hostname: str,
        logon_id: str,
        observed_at: str,
        seconds: int = 5,
    ) -> list[dict[str, Any]]:
        try:
            center = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            return []
        lower = (center - timedelta(seconds=seconds)).isoformat()
        upper = (center + timedelta(seconds=seconds)).isoformat()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence_events
                WHERE artifact_id = ? AND hostname = ? AND logon_id = ?
                  AND observed_at BETWEEN ? AND ?
                ORDER BY observed_at ASC
                """,
                (artifact_id, hostname, logon_id, lower, upper),
            ).fetchall()
        return [dict(row) for row in rows]

    def artifact_for_session(
        self,
        *,
        hostname: str,
        logon_id: str,
        observed_at: str,
        seconds: int = 5,
    ) -> dict[str, Any] | None:
        try:
            center = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        lower = (center - timedelta(seconds=seconds)).isoformat()
        upper = (center + timedelta(seconds=seconds)).isoformat()
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT a.*
                FROM evidence_events e
                JOIN artifacts a ON a.id = e.artifact_id
                WHERE e.hostname = ? AND e.logon_id = ?
                  AND e.observed_at BETWEEN ? AND ?
                ORDER BY e.observed_at DESC LIMIT 1
                """,
                (hostname, logon_id, lower, upper),
            ).fetchone()
        return dict(row) if row else None

    def update_strength(self, event_ids: list[str], strength: str, summary_suffix: str) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self.connect() as connection:
            connection.execute(
                f"""
                UPDATE evidence_events
                SET strength = ?, summary = summary || ?
                WHERE id IN ({placeholders}) AND strength = 'candidate'
                """,
                [strength, summary_suffix, *event_ids],
            )

    def counts(self) -> dict[str, int]:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM artifacts) AS artifact_count,
                  (SELECT COUNT(*) FROM evidence_events) AS event_count,
                  (SELECT COUNT(*) FROM evidence_events WHERE source = 'janus_pixel') AS pixel_hits,
                  (SELECT COUNT(*) FROM evidence_events WHERE source = 'canary') AS canary_hits,
                  (SELECT COUNT(*) FROM evidence_events WHERE source = 'wazuh') AS wazuh_events,
                  (SELECT COUNT(*) FROM evidence_events WHERE strength IN ('confirmed','corroborated')) AS strong_events
                """
            ).fetchone()
        return {key: int(row[key]) for key in row.keys()}

    def set_state(self, key: str, value: Any) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO runtime_state (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (key, json.dumps(value, ensure_ascii=False), utc_now()),
            )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value_json FROM runtime_state WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value_json"]) if row else default
