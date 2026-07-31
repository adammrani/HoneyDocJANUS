"""CLI : analyse un JSON Wazuh contre la base des honeydocuments."""

import argparse
import json
from pathlib import Path
from typing import Any

from .detection.pipeline import analyze_wazuh_alert
from .registry.sqlite_registry import SqliteDecoyRegistry


def _read_alert(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Le fichier d'alerte doit contenir un objet JSON.")
    return payload


def _serialize_analysis(alert_path: Path, database_path: Path) -> dict[str, Any]:
    registry = SqliteDecoyRegistry(database_path)
    analysis = analyze_wazuh_alert(_read_alert(alert_path), registry)
    event = analysis.event

    result: dict[str, Any] = {
        "detected": analysis.detected,
        "event": {
            "event_id": event.event_id,
            "hostname": event.hostname,
            "user": event.user,
            "path": event.path,
            "action": event.action.value,
            "timestamp": event.timestamp.isoformat(),
            "process_name": event.process_name,
            "process_id": event.process_id,
            "agent_id": event.agent_id,
            "event_record_id": event.event_record_id,
        },
    }

    if analysis.decoy is None or analysis.verdict is None:
        result["reason"] = "Aucun honeydocument actif ne correspond au chemin."
        return result

    result["decoy"] = {
        "instance_id": analysis.decoy.instance_id,
        "filename": analysis.decoy.filename,
        "deployment_path": analysis.decoy.deployment_path,
    }
    result["verdict"] = {
        "level": analysis.verdict.level.value,
        "score": analysis.verdict.score,
        "reasons": analysis.verdict.reasons,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Corrèle une alerte Wazuh 4663 avec les honeydocuments JANUS."
    )
    parser.add_argument("alert", type=Path, help="Fichier JSON de l'alerte Wazuh")
    parser.add_argument("database", type=Path, help="Base SQLite honeydocs.db")
    arguments = parser.parse_args()

    print(
        json.dumps(
            _serialize_analysis(arguments.alert, arguments.database),
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
