"""Tests de la persistance des verdicts Wazuh."""

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.detection.pipeline import DetectionAnalysis  # noqa: E402
from janus_v2.domain.models import (  # noqa: E402
    DecoyInstance,
    DetectionVerdict,
    EventAction,
    SecurityEvent,
    VerdictLevel,
)
from janus_v2.registry.wazuh_detection_store import (  # noqa: E402
    SqliteWazuhDetectionStore,
)


class WazuhDetectionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "janus.db"
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                """
                CREATE TABLE honeydocs (
                    id INTEGER PRIMARY KEY,
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    doc_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    ttl_hours INTEGER NOT NULL,
                    active INTEGER NOT NULL
                )
                """
            )
            connection.commit()
        self.store = SqliteWazuhDetectionStore(self.database_path)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _analysis(self) -> DetectionAnalysis:
        event = SecurityEvent(
            event_id="wazuh-001",
            hostname="LAB-PC",
            user=r"LAB\analyst",
            path=r"C:\HoneyDocJANUS\data\shared\budget.docx",
            action=EventAction.READ,
            timestamp=datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc),
            source="wazuh:windows:4663",
            process_name=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            process_id="0x42",
            access_mask="0x1",
            agent_id="001",
            event_record_id="737001",
        )
        decoy = DecoyInstance(
            instance_id="honeydoc-9",
            filename="budget.docx",
            deployment_path=event.path,
            expected_hostname=None,
            expected_user=None,
        )
        verdict = DetectionVerdict(
            level=VerdictLevel.LOW,
            score=40,
            reasons=["Leurre actif."],
            decoy_instance_id=decoy.instance_id,
            event_id=event.event_id,
        )
        return DetectionAnalysis(event=event, decoy=decoy, verdict=verdict)

    def test_duplicate_event_is_stored_only_once(self) -> None:
        alert = {
            "_id": "index-document-1",
            "_source": {
                "id": "wazuh-001",
                "rule": {"id": "100101"},
            },
        }
        analysis = self._analysis()

        self.assertTrue(self.store.record(alert, analysis))
        self.assertFalse(self.store.record(alert, analysis))
        self.assertEqual(self.store.count(), 1)

        item = self.store.list_detections()[0]
        self.assertEqual(item["honeydoc_id"], 9)
        self.assertTrue(item["matched"])
        self.assertTrue(item["detected"])
        self.assertFalse(item["suppressed"])
        self.assertEqual(item["action"], "read")
        self.assertEqual(item["wazuh_rule_id"], "100101")
        self.assertEqual(item["verdict_reasons"], ["Leurre actif."])
        self.assertEqual(len(item["raw_alert_sha256"]), 64)

    def test_cursor_round_trip(self) -> None:
        self.assertIsNone(self.store.get_cursor())

        self.store.set_cursor([1784712013873, "document-id"])

        self.assertEqual(
            self.store.get_cursor(),
            [1784712013873, "document-id"],
        )


if __name__ == "__main__":
    unittest.main()
