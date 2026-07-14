"""
src/core/database.py
SQLite persistence layer.

Three tables (see project spec):
  honeydocs  — one row per deployed decoy document
  tokens     — one row per Canarytoken bound to a honeydoc
  alerts     — one row per triggered detection (token/CI1/CI3)

All access goes through the `get_conn()` context manager, which yields a
connection whose rows behave like dicts (`sqlite3.Row`).
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from src.core.config import get_settings

_settings = get_settings()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with Row factory, committing on success."""
    _settings.ensure_dirs()
    conn = sqlite3.connect(_settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    """Create the three tables if they do not already exist."""
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS honeydocs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT    NOT NULL,
                filepath    TEXT    NOT NULL,
                doc_type    TEXT    NOT NULL,
                target_dir  TEXT,
                created_at  TEXT    NOT NULL,
                ttl_hours   INTEGER NOT NULL DEFAULT 72,
                active      INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS tokens (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                honeydoc_id   INTEGER,
                token_id      TEXT NOT NULL,
                token_url     TEXT,
                callback_url  TEXT,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (honeydoc_id) REFERENCES honeydocs (id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id      TEXT,
                honeydoc_id   INTEGER,
                triggered_at  TEXT NOT NULL,
                src_ip        TEXT,
                user_agent    TEXT,
                geo_country   TEXT,
                geo_city      TEXT,
                os_guess      TEXT,
                browser_guess TEXT,
                raw_payload   TEXT,
                FOREIGN KEY (honeydoc_id) REFERENCES honeydocs (id)
            );
            """
        )


# ── honeydocs ────────────────────────────────────────────

def insert_honeydoc(
    filename: str,
    filepath: str,
    doc_type: str,
    target_dir: str = "",
    ttl_hours: int = 72,
) -> int:
    """Insert a honeydoc row and return its new id."""
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO honeydocs
                (filename, filepath, doc_type, target_dir, created_at, ttl_hours, active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (filename, filepath, doc_type, target_dir, _now(), ttl_hours),
        )
        return int(cur.lastrowid)


def list_honeydocs() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM honeydocs ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def list_active_honeydocs() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM honeydocs WHERE active = 1 ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def deactivate_honeydoc(honeydoc_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE honeydocs SET active = 0 WHERE id = ?", (honeydoc_id,)
        )


# ── tokens ───────────────────────────────────────────────

def insert_token(
    honeydoc_id: int,
    token_id: str,
    token_url: str,
    callback_url: str,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tokens
                (honeydoc_id, token_id, token_url, callback_url, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (honeydoc_id, token_id, token_url, callback_url, _now()),
        )
        return int(cur.lastrowid)


def get_token_by_id(token_id: str) -> Optional[dict]:
    """Return the token row for a given token_id, or None."""
    if not token_id:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tokens WHERE token_id = ? ORDER BY id DESC LIMIT 1",
            (token_id,),
        ).fetchone()
        return dict(row) if row else None


# ── alerts ───────────────────────────────────────────────

def insert_alert(
    token_id: Optional[str],
    honeydoc_id: Optional[int],
    src_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    geo_country: Optional[str] = None,
    geo_city: Optional[str] = None,
    os_guess: Optional[str] = None,
    browser_guess: Optional[str] = None,
    raw_payload: Optional[dict] = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts
                (token_id, honeydoc_id, triggered_at, src_ip, user_agent,
                 geo_country, geo_city, os_guess, browser_guess, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                honeydoc_id,
                _now(),
                src_ip,
                user_agent,
                geo_country,
                geo_city,
                os_guess,
                browser_guess,
                json.dumps(raw_payload or {}, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)


def list_alerts(limit: int = 100) -> list[dict]:
    """Return recent alerts joined with their honeydoc filename."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT a.*, h.filename AS honeydoc_filename, h.doc_type AS honeydoc_type
            FROM alerts a
            LEFT JOIN honeydocs h ON a.honeydoc_id = h.id
            ORDER BY a.triggered_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
