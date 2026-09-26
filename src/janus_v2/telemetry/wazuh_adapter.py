"""Conversion des événements Wazuh 4663 en objets métier JANUS."""

from datetime import datetime
from typing import Any

from ..domain.models import EventAction, SecurityEvent


def _detect_action(
    accesses: str = "",
    access_mask: str = "",
    access_list: str = "",
) -> EventAction:
    normalized_accesses = accesses.casefold()
    normalized_access_list = access_list.casefold()

    try:
        mask_value = int(access_mask, 16) if access_mask else 0
    except ValueError:
        mask_value = 0

    if "delete" in normalized_accesses or mask_value & 0x10000:
        return EventAction.DELETE

    if (
        "writedata" in normalized_accesses
        or "appenddata" in normalized_accesses
        or mask_value & 0x2
        or mask_value & 0x4
    ):
        return EventAction.MODIFY

    if (
        "readdata" in normalized_accesses
        or "%%4416" in normalized_access_list
        or mask_value & 0x1
    ):
        return EventAction.READ

    return EventAction.UNKNOWN


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"

    if len(value) >= 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = f"{value[:-2]}:{value[-2:]}"

    return datetime.fromisoformat(value)


def _normalize_windows_path(path: str) -> str:
    """Tolère aussi les chemins Windows accidentellement double-échappés.

    Un JSON correctement décodé contient déjà des séparateurs simples. Le
    remplacement n'est appliqué qu'à un chemin avec lecteur ``C:\\\\...`` afin
    de ne pas casser un véritable chemin UNC ``\\\\serveur\\partage``.
    """

    if len(path) >= 4 and path[1] == ":" and path[2:4] == "\\\\":
        return path.replace("\\\\", "\\")
    return path


def _unwrap_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Extrait ``_source`` lorsqu'un résultat OpenSearch est fourni."""

    source = alert.get("_source")
    if isinstance(source, dict):
        return source
    return alert


def parse_wazuh_event(alert: dict[str, Any]) -> SecurityEvent:
    alert_source = _unwrap_alert(alert)

    try:
        timestamp = _parse_timestamp(str(alert_source["timestamp"]))

        agent = alert_source["agent"]
        windows_data = alert_source["data"]["win"]
        system_data = windows_data["system"]
        event_data = windows_data["eventdata"]

        event_id = str(system_data["eventID"])
        hostname = str(system_data.get("computer") or agent.get("name") or "")

        domain = str(event_data.get("subjectDomainName") or "")
        username = str(event_data["subjectUserName"])
        path = _normalize_windows_path(str(event_data["objectName"]))

        accesses = str(event_data.get("accesses", ""))
        access_mask = str(event_data.get("accessMask", ""))
        access_list = str(event_data.get("accessList", ""))

        event_record_id = str(system_data.get("eventRecordID") or "") or None
        wazuh_id = str(
            alert_source.get("id")
            or alert.get("_id")
            or event_record_id
            or ""
        )

        if not wazuh_id or not hostname:
            raise ValueError("Identifiant ou nom de machine absent.")

    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            "L'événement Wazuh ne contient pas les champs attendus."
        ) from error

    if event_id != "4663":
        raise ValueError(
            f"Événement Windows non supporté pour le moment : {event_id}."
        )

    return SecurityEvent(
        event_id=wazuh_id,
        hostname=hostname,
        user=fr"{domain}\{username}" if domain else username,
        path=path,
        action=_detect_action(
            accesses=accesses,
            access_mask=access_mask,
            access_list=access_list,
        ),
        timestamp=timestamp,
        source="wazuh:windows:4663",
        process_name=(
            _normalize_windows_path(str(event_data["processName"]))
            if event_data.get("processName")
            else None
        ),
        process_id=(
            str(event_data["processId"])
            if event_data.get("processId") is not None
            else None
        ),
        access_mask=access_mask or None,
        agent_id=(
            str(agent["id"])
            if agent.get("id") is not None
            else None
        ),
        event_record_id=event_record_id,
    )
