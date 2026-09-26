"""Construction prudente d'un chemin d'activité à partir de preuves liées."""

from __future__ import annotations

from typing import Any


def build_attack_timeline(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Ordonne les preuves et expose le point d'entrée lorsqu'il est observé.

    La corrélation repose uniquement sur le Logon ID et l'hôte fournis par
    Windows. Elle ne fusionne pas deux sessions sur la seule base d'un nom
    d'utilisateur, afin de limiter les faux rapprochements.
    """

    ordered = sorted(signals, key=lambda item: str(item.get("observed_at") or ""))
    entry = next((item for item in ordered if item.get("kind") == "logon"), None)
    entry_point = None
    if entry is not None:
        entry_point = {
            "observed_at": entry.get("observed_at"),
            "channel": entry.get("entry_channel"),
            "source_ip": entry.get("source_ip"),
            "source_port": entry.get("source_port"),
            "user": entry.get("user"),
            "hostname": entry.get("hostname"),
            "evidence_event_id": entry.get("evidence_event_id"),
            "confidence": entry.get("confidence"),
        }

    return {
        "correlation": "same_hostname_and_logon_or_session_id",
        "entry_point": entry_point,
        "steps": ordered,
        "step_count": len(ordered),
        "limitations": [
            "Un événement sans Logon ID ne peut pas être ajouté fiablement à cette session.",
            "L'absence d'un événement ne prouve pas l'absence d'une action.",
            "Après un redémarrage, un identifiant de session peut être réutilisé; borner l'analyse dans le temps.",
        ],
    }
