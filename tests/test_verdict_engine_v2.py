"""Tests du moteur de verdict de JANUS v2."""

import sys
import unittest
from datetime import datetime
from pathlib import Path


# Permet d'importer janus_v2 depuis le dossier src.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = PROJECT_ROOT / "src"
SHARED_DIRECTORY = PROJECT_ROOT / "data" / "shared"
sys.path.insert(0, str(SRC_DIRECTORY))

from janus_v2.domain.models import (  # noqa: E402
    DecoyInstance,
    EventAction,
    SecurityEvent,
    VerdictLevel,
)
from janus_v2.verdict.engine import build_verdict  # noqa: E402


class VerdictEngineTests(unittest.TestCase):
    """Vérifie les décisions élémentaires du moteur."""

    def test_expected_user_and_machine_produce_low_verdict(self) -> None:
        decoy = DecoyInstance(
            instance_id="decoy-001",
            filename="Budget_Previsionnel_2027.docx",
            deployment_path=str(
                SHARED_DIRECTORY / "Budget_Previsionnel_2027.docx"
            ),
            expected_hostname="FINANCE-PC-01",
            expected_user=r"COMPANY\alice",
        )

        event = SecurityEvent(
            event_id="event-normal-001",
            hostname="FINANCE-PC-01",
            user=r"COMPANY\alice",
            path=str(SHARED_DIRECTORY / "Budget_Previsionnel_2027.docx"),
            action=EventAction.READ,
            timestamp=datetime.now(),
        )

        verdict = build_verdict(
            event=event,
            decoy=decoy,
        )

        self.assertEqual(verdict.level, VerdictLevel.LOW)
        self.assertEqual(verdict.score, 40)
        self.assertEqual(verdict.decoy_instance_id, "decoy-001")

        self.assertIn(
            "La machine correspond à la machine attendue.",
            verdict.reasons,
        )
        self.assertIn(
            "L'utilisateur correspond à l'utilisateur attendu.",
            verdict.reasons,
        )

    def test_decoy_without_expected_target_does_not_crash(self) -> None:
        decoy = DecoyInstance(
            instance_id="decoy-shared-001",
            filename="Planning_Equipe.docx",
            deployment_path=str(SHARED_DIRECTORY / "Planning_Equipe.docx"),
            expected_hostname=None,
            expected_user=None,
        )

        event = SecurityEvent(
            event_id="event-shared-001",
            hostname="EMPLOYEE-PC-03",
            user=r"COMPANY\bob",
            path=str(SHARED_DIRECTORY / "Planning_Equipe.docx"),
            action=EventAction.READ,
            timestamp=datetime.now(),
        )

        verdict = build_verdict(event=event, decoy=decoy)

        self.assertEqual(verdict.level, VerdictLevel.LOW)
        self.assertEqual(verdict.score, 40)

        self.assertIn(
            "Aucune machine attendue n'est définie pour ce leurre.",
            verdict.reasons,
        )
        self.assertIn(
            "Aucun utilisateur attendu n'est défini pour ce leurre.",
            verdict.reasons,
        )


if __name__ == "__main__":
    unittest.main()
