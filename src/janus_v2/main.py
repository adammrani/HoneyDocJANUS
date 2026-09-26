from .domain.models import DecoyInstance
from .domain.models import SecurityEvent
from .domain.models import EventAction
from .correlation.engine import correlate_event
from .verdict.engine import build_verdict
from .registry.decoy_registry import DecoyRegistry
from datetime import datetime
from pathlib import Path



PROJECT_ROOT = Path(__file__).resolve().parents[2]
SHARED_DIRECTORY = PROJECT_ROOT / "data" / "shared"


def main() -> None:
    filename = "Budget_Previsionnel_2027.docx"
    deployment_path = str(SHARED_DIRECTORY / filename)

    decoy = DecoyInstance(
        instance_id="decoy-001",
        filename=filename,
        deployment_path=deployment_path,
        expected_hostname="FINANCE-PC-01",
        expected_user=r"COMPANY\alice",
    )

    registry = DecoyRegistry()
    registry.register(decoy)

    event = SecurityEvent(
        event_id="event-001",
        hostname="UNKNOWN-PC-07",
        user=r"COMPANY\adam",
        path=deployment_path,
        action=EventAction.READ,
        timestamp=datetime.now(),
    )

    matched_decoy = correlate_event(
        event=event,
        decoys=registry.list_active(),
    )

    print("=== Leurre enregistré ===")
    print(f"Identifiant : {decoy.instance_id}")
    print(f"Fichier     : {decoy.filename}")
    print(f"Chemin      : {decoy.deployment_path}")
    print(f"Machine     : {decoy.expected_hostname}")
    print(f"Utilisateur : {decoy.expected_user}")
    print(f"Statut      : {decoy.status.value}")

    print()
    print("=== Événement observé ===")
    print(f"Identifiant : {event.event_id}")
    print(f"Chemin      : {event.path}")
    print(f"Machine     : {event.hostname}")
    print(f"Utilisateur : {event.user}")
    print(f"Action      : {event.action.value}")
    print(f"Source      : {event.source}")
    print(f"Date        : {event.timestamp}")

    print()
    print("=== Résultat de la corrélation ===")

    if matched_decoy is None:
        print("Aucun leurre actif ne correspond à cet événement.")
    else:
        print("Leurre reconnu.")
        print(f"Instance : {matched_decoy.instance_id}")
        print(f"Fichier  : {matched_decoy.filename}")
        verdict = build_verdict(
            event=event,
            decoy=matched_decoy,
        )

        print()
        print("=== Verdict JANUS ===")
        print(f"Niveau : {verdict.level.value}")
        print(f"Score  : {verdict.score}")

        print("Raisons :")
        for reason in verdict.reasons:
            print(f"- {reason}")


if __name__ == "__main__":
    main()
