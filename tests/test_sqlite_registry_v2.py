"""Tests du pont entre la base historique et le registre JANUS v2."""

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SHARED_DIRECTORY = PROJECT_ROOT / "data" / "shared"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.registry.sqlite_registry import SqliteDecoyRegistry  # noqa: E402


class SqliteDecoyRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "janus.db"

        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.executescript(
                """
                CREATE TABLE honeydocs (
                    id INTEGER PRIMARY KEY,
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    doc_type TEXT NOT NULL,
                    target_dir TEXT,
                    created_at TEXT NOT NULL,
                    ttl_hours INTEGER NOT NULL,
                    active INTEGER NOT NULL
                );
                """
            )
            connection.executemany(
                """
                INSERT INTO honeydocs
                    (id, filename, filepath, doc_type, target_dir,
                     created_at, ttl_hours, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        1,
                        "Budget_IA.docx",
                        str(SHARED_DIRECTORY / "Budget_IA.docx"),
                        "financial_report",
                        str(SHARED_DIRECTORY),
                        "2026-07-19T10:00:00+00:00",
                        72,
                        1,
                    ),
                    (
                        2,
                        "Secrets_IA.env",
                        str(SHARED_DIRECTORY / "Secrets_IA.env"),
                        "environment_file",
                        str(SHARED_DIRECTORY),
                        "2026-07-19T10:01:00+00:00",
                        72,
                        1,
                    ),
                    (
                        3,
                        "Ancien.pdf",
                        str(SHARED_DIRECTORY / "Ancien.pdf"),
                        "pdf",
                        str(SHARED_DIRECTORY),
                        "2026-07-18T10:00:00+00:00",
                        72,
                        0,
                    ),
                ],
            )
            connection.commit()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_only_active_honeydocs_are_loaded_for_every_format(self) -> None:
        registry = SqliteDecoyRegistry(self.database_path)

        decoys = registry.list_active()

        self.assertEqual(
            {decoy.filename for decoy in decoys},
            {"Budget_IA.docx", "Secrets_IA.env"},
        )
        self.assertEqual(
            {decoy.instance_id for decoy in decoys},
            {"honeydoc-1", "honeydoc-2"},
        )
        self.assertTrue(all(decoy.expected_user is None for decoy in decoys))

    def test_missing_database_is_not_created_silently(self) -> None:
        missing_path = Path(self.temporary_directory.name) / "missing.db"
        registry = SqliteDecoyRegistry(missing_path)

        with self.assertRaises(FileNotFoundError):
            registry.list_active()

        self.assertFalse(missing_path.exists())


if __name__ == "__main__":
    unittest.main()
