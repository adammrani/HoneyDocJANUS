"""Apply the bounded JANUS context-retention policy to the local database."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.janus_v2.registry.security_signal_store import (  # noqa: E402
    SqliteSecuritySignalStore,
)


def table_counts(database_path: Path) -> dict[str, int]:
    with sqlite3.connect(database_path) as connection:
        return {
            "security_signals": int(
                connection.execute("SELECT COUNT(*) FROM security_signals").fetchone()[0]
            ),
            "raw_evidence": int(
                connection.execute("SELECT COUNT(*) FROM raw_evidence").fetchone()[0]
            ),
            "wazuh_detections": int(
                connection.execute("SELECT COUNT(*) FROM wazuh_detections").fetchone()[0]
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="data/honeydocs.db")
    parser.add_argument("--retention-days", type=int, default=3)
    parser.add_argument("--max-context-signals", type=int, default=10000)
    parser.add_argument("--max-unlinked-raw", type=int, default=1000)
    parser.add_argument("--vacuum", action="store_true")
    args = parser.parse_args()

    database_path = Path(args.database)
    if not database_path.is_absolute():
        database_path = PROJECT_ROOT / database_path
    database_path = database_path.resolve()
    if not database_path.is_file():
        raise SystemExit(f"Base JANUS absente : {database_path}")

    before = table_counts(database_path)
    result = SqliteSecuritySignalStore(database_path).prune_context(
        retention_days=args.retention_days,
        max_context_signals=args.max_context_signals,
        max_unlinked_raw=args.max_unlinked_raw,
    )
    if args.vacuum:
        with sqlite3.connect(database_path, timeout=300) as connection:
            connection.execute("PRAGMA busy_timeout = 300000")
            connection.execute("VACUUM")
    after = table_counts(database_path)
    print(
        json.dumps(
            {
                "database": str(database_path),
                "before": before,
                "retention": result,
                "after": after,
                "vacuum": bool(args.vacuum),
                "file_bytes": database_path.stat().st_size,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
