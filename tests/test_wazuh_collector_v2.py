"""Tests du collecteur automatique Wazuh vers JANUS."""

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.detection.wazuh_collector import (  # noqa: E402
    WazuhCollector,
    WazuhCollectorConfig,
)
from janus_v2.domain.models import DecoyInstance  # noqa: E402
from janus_v2.registry.wazuh_detection_store import (  # noqa: E402
    SqliteWazuhDetectionStore,
)
from janus_v2.registry.security_signal_store import (  # noqa: E402
    SqliteSecuritySignalStore,
)
from janus_v2.telemetry.wazuh_indexer_client import (  # noqa: E402
    WazuhAlertPage,
)


SHARED_PATH = r"C:\HoneyDocJANUS\data\shared\budget.docx"


def _alert(
    document_id: str,
    event_id: str,
    timestamp: str,
    path: str,
    process_name: str,
    access_mask: str,
    sort_timestamp: int,
) -> dict:
    return {
        "_id": document_id,
        "sort": [sort_timestamp, document_id],
        "_source": {
            "id": event_id,
            "timestamp": timestamp,
            "agent": {"id": "001", "name": "LAB-PC"},
            "data": {
                "win": {
                    "system": {
                        "eventID": "4663",
                        "computer": "LAB-PC",
                        "eventRecordID": event_id,
                    },
                    "eventdata": {
                        "subjectDomainName": "LAB",
                        "subjectUserName": "analyst",
                        "objectName": path,
                        "processName": process_name,
                        "processId": "0x42",
                        "accessMask": access_mask,
                    },
                }
            },
            "rule": {"id": "100100"},
        },
    }


class FakeSource:
    def __init__(self, alerts: list[dict]) -> None:
        self.alerts = alerts
        self.calls = []

    def fetch_alerts(self, **arguments) -> WazuhAlertPage:
        self.calls.append(arguments)
        search_after = arguments.get("search_after")
        start = 0
        if search_after is not None:
            for index, alert in enumerate(self.alerts):
                if alert["sort"] == search_after:
                    start = index + 1
                    break
        batch_size = arguments["batch_size"]
        page = self.alerts[start : start + batch_size]
        return WazuhAlertPage(
            alerts=page,
            next_search_after=(page[-1]["sort"] if page else None),
        )


class FakeRegistry:
    def __init__(self, decoy: DecoyInstance) -> None:
        self.decoy = decoy

    def list_active(self) -> list[DecoyInstance]:
        return [self.decoy]


class FailingSource:
    def fetch_alerts(self, **arguments) -> WazuhAlertPage:
        raise RuntimeError("indexer offline")


class StopAfterFirstWait:
    def __init__(self) -> None:
        self.stopped = False

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, timeout: float) -> bool:
        self.stopped = True
        return True


class WazuhCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "janus.db"
        self.store = SqliteWazuhDetectionStore(database_path)
        self.store.initialize()
        self.evidence_store = SqliteSecuritySignalStore(database_path)
        self.evidence_store.initialize()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_collects_pages_deduplicates_and_suppresses_deployment(self) -> None:
        alerts = [
            _alert(
                "doc-a",
                "event-a",
                "2026-07-22T10:00:01+0000",
                SHARED_PATH,
                r"C:\Python314\python.exe",
                "0x2",
                1000,
            ),
            _alert(
                "doc-b",
                "event-b",
                "2026-07-22T10:00:20+0000",
                SHARED_PATH,
                r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                "0x1",
                2000,
            ),
            _alert(
                "doc-c",
                "event-c",
                "2026-07-22T10:00:30+0000",
                r"C:\HoneyDocJANUS\data\shared\ordinary.txt",
                r"C:\Windows\explorer.exe",
                "0x1",
                3000,
            ),
        ]
        source = FakeSource(alerts)
        registry = FakeRegistry(
            DecoyInstance(
                instance_id="honeydoc-9",
                filename="budget.docx",
                deployment_path=SHARED_PATH,
                expected_hostname=None,
                expected_user=None,
                created_at=datetime(
                    2026,
                    7,
                    22,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            )
        )
        collector = WazuhCollector(
            source=source,
            registry=registry,
            store=self.store,
            evidence_store=self.evidence_store,
            config=WazuhCollectorConfig(
                batch_size=2,
                settle_seconds=0,
                overlap_seconds=120,
                trusted_process_path=r"C:\Python314\python.exe",
                deployment_grace_seconds=15,
            ),
            clock_epoch_ms=lambda: 5000,
        )

        self.assertEqual(collector.run_once(), 3)
        self.assertEqual(self.store.count(), 3)
        self.assertEqual(collector.run_once(), 0)
        self.assertEqual(self.store.count(), 3)

        detections = self.store.list_detections(limit=10)
        suppressed = [item for item in detections if item["suppressed"]]
        detected = [item for item in detections if item["detected"]]
        unmatched = [item for item in detections if not item["matched"]]
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["action"], "modify")
        self.assertEqual(len(detected), 1)
        self.assertEqual(detected[0]["action"], "read")
        self.assertEqual(len(unmatched), 1)
        self.assertEqual(self.store.get_cursor(), [3000, "doc-c"])
        self.assertGreaterEqual(len(source.calls), 4)

        evidence = self.evidence_store.list_raw_evidence(limit=10)
        self.assertEqual(len(evidence), 3)
        self.assertTrue(all(item["normalization_status"] == "normalized" for item in evidence))
        self.assertTrue(all(len(item["raw_payload_sha256"]) == 64 for item in evidence))
        self.assertEqual(self.evidence_store.count(), 3)
        status = collector.status()
        self.assertEqual(status["last_batch_evidence_normalized"], 3)
        self.assertEqual(status["last_batch_evidence_pending"], 0)

    def test_indexer_failure_is_reported_without_crashing_service(self) -> None:
        registry = FakeRegistry(
            DecoyInstance(
                instance_id="honeydoc-1",
                filename="budget.docx",
                deployment_path=SHARED_PATH,
                expected_hostname=None,
                expected_user=None,
            )
        )
        collector = WazuhCollector(
            source=FailingSource(),
            registry=registry,
            store=self.store,
            config=WazuhCollectorConfig(poll_interval_seconds=0.01),
            clock_epoch_ms=lambda: 5000,
        )

        collector.run_forever(StopAfterFirstWait())  # type: ignore[arg-type]

        status = collector.status()
        self.assertFalse(status["running"])
        self.assertIn("indexer offline", status["last_error"])
        self.assertEqual(status["consecutive_errors"], 1)


if __name__ == "__main__":
    unittest.main()
