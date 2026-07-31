"""Tests de l'adaptateur Wazuh de JANUS v2."""

import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SHARED_DIRECTORY = PROJECT_ROOT / "data" / "shared"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.domain.models import EventAction  # noqa: E402
from janus_v2.telemetry.wazuh_adapter import parse_wazuh_event  # noqa: E402


class WazuhAdapterTests(unittest.TestCase):
    """Vérifie les formats historique et réel de Wazuh."""

    def test_legacy_simulated_event_remains_supported(self) -> None:
        alert = {
            "id": "wazuh-event-001",
            "timestamp": "2026-07-15T17:30:00+01:00",
            "agent": {"id": "001", "name": "UNKNOWN-PC-07"},
            "data": {
                "win": {
                    "system": {"eventID": "4663"},
                    "eventdata": {
                        "subjectDomainName": "COMPANY",
                        "subjectUserName": "adam",
                        "objectName": str(
                            SHARED_DIRECTORY / "Budget_Previsionnel_2027.docx"
                        ),
                        "accesses": "ReadData",
                    },
                }
            },
        }

        event = parse_wazuh_event(alert)

        self.assertEqual(event.event_id, "wazuh-event-001")
        self.assertEqual(event.hostname, "UNKNOWN-PC-07")
        self.assertEqual(event.user, r"COMPANY\adam")
        self.assertEqual(event.action, EventAction.READ)
        self.assertEqual(event.source, "wazuh:windows:4663")

    def test_real_threat_hunting_result_preserves_evidence(self) -> None:
        fixture_path = (
            PROJECT_ROOT
            / "tests"
            / "fixtures"
            / "wazuh_4663_real_anonymized.json"
        )
        alert = json.loads(fixture_path.read_text(encoding="utf-8"))

        event = parse_wazuh_event(alert)

        self.assertEqual(event.event_id, "1784457380.648711")
        self.assertEqual(event.hostname, "LAB-WINDOWS")
        self.assertEqual(event.user, r"LAB\analyst")
        self.assertEqual(
            event.path,
            r"C:\HoneyDocJANUS\data\shared\Budget_IA_2026.docx",
        )
        self.assertEqual(event.action, EventAction.READ)
        self.assertEqual(event.process_name, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        self.assertEqual(event.process_id, "0x42")
        self.assertEqual(event.access_mask, "0x1")
        self.assertEqual(event.agent_id, "001")
        self.assertEqual(event.event_record_id, "674776")
        self.assertEqual(
            event.timestamp.isoformat(),
            "2026-07-19T10:36:20.446000+00:00",
        )

    def test_non_4663_event_is_rejected(self) -> None:
        alert = {
            "id": "event-4656",
            "timestamp": "2026-07-19T10:36:20Z",
            "agent": {"id": "001", "name": "LAB-WINDOWS"},
            "data": {
                "win": {
                    "system": {"eventID": "4656"},
                    "eventdata": {
                        "subjectUserName": "analyst",
                        "objectName": str(SHARED_DIRECTORY / "file.pdf"),
                    },
                }
            },
        }

        with self.assertRaisesRegex(ValueError, "non supporté"):
            parse_wazuh_event(alert)

    def test_missing_required_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "champs attendus"):
            parse_wazuh_event({"id": "incomplete"})


if __name__ == "__main__":
    unittest.main()
