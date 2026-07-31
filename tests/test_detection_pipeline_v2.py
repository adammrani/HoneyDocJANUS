"""Tests de bout en bout : Wazuh -> SQLite -> corrélation -> verdict."""

import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SHARED_DIRECTORY = PROJECT_ROOT / "data" / "shared"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.detection.pipeline import analyze_wazuh_alert  # noqa: E402
from janus_v2.domain.models import EventAction, VerdictLevel  # noqa: E402
from janus_v2.registry.sqlite_registry import SqliteDecoyRegistry  # noqa: E402


FORMATS = (
    "Budget_IA.docx",
    "Rapport_IA.pdf",
    "Comptes_IA.xlsx",
    "Archive_IA.zip",
    "Secrets_IA.env",
    "Config_IA.yaml",
    "Service_IA.json",
)


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "janus.db"
        self.fixture = json.loads(
            (
                PROJECT_ROOT
                / "tests"
                / "fixtures"
                / "wazuh_4663_real_anonymized.json"
            ).read_text(encoding="utf-8")
        )

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
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                [
                    (
                        index,
                        filename,
                        str(SHARED_DIRECTORY / filename),
                        Path(filename).suffix or "extensionless",
                        str(SHARED_DIRECTORY),
                        f"2026-07-19T10:00:{index:02d}+00:00",
                        72,
                    )
                    for index, filename in enumerate(FORMATS, start=1)
                ],
            )
            connection.commit()

        self.registry = SqliteDecoyRegistry(self.database_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _alert_for(self, filename: str) -> dict:
        alert = copy.deepcopy(self.fixture)
        alert["_source"]["data"]["win"]["eventdata"]["objectName"] = str(
            SHARED_DIRECTORY / filename
        )
        return alert

    def test_every_registered_honeydoc_format_is_detected(self) -> None:
        for filename in FORMATS:
            with self.subTest(filename=filename):
                analysis = analyze_wazuh_alert(
                    self._alert_for(filename),
                    self.registry,
                )

                self.assertTrue(analysis.detected)
                self.assertIsNotNone(analysis.decoy)
                self.assertIsNotNone(analysis.verdict)
                self.assertEqual(analysis.decoy.filename, filename)
                self.assertEqual(analysis.event.action, EventAction.READ)
                self.assertEqual(analysis.verdict.level, VerdictLevel.LOW)
                self.assertEqual(analysis.verdict.score, 40)

    def test_unregistered_file_does_not_become_a_janus_detection(self) -> None:
        analysis = analyze_wazuh_alert(
            self._alert_for("document_ordinaire.txt"),
            self.registry,
        )

        self.assertFalse(analysis.detected)
        self.assertIsNone(analysis.decoy)
        self.assertIsNone(analysis.verdict)

    def test_windows_paths_are_matched_case_insensitively(self) -> None:
        alert = self._alert_for("budget_ia.DOCX")

        analysis = analyze_wazuh_alert(alert, self.registry)

        self.assertTrue(analysis.detected)
        self.assertEqual(analysis.decoy.filename, "Budget_IA.docx")


if __name__ == "__main__":
    unittest.main()
