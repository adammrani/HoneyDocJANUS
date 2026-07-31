"""Normalisation forensique des événements Windows reçus par Wazuh."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..domain.signals import (
    EvidenceConfidence,
    ObservedAction,
    SecuritySignal,
    SignalKind,
)


_SYSMON_PROVIDER = "microsoft-windows-sysmon"
_LOGON_TYPES = {
    "2": "local_interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network_cleartext",
    "9": "new_credentials",
    "10": "rdp",
    "11": "cached_interactive",
    "12": "cached_rdp",
    "13": "cached_unlock",
}


def _unwrap(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("_source")
    return source if isinstance(source, dict) else alert


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    if len(value) >= 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = f"{value[:-2]}:{value[-2:]}"
    return datetime.fromisoformat(value)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text


def _user(event: dict[str, Any], prefix: str) -> tuple[str | None, str | None]:
    username = _clean(event.get(f"{prefix}UserName"))
    domain = _clean(event.get(f"{prefix}DomainName"))
    sid = _clean(event.get(f"{prefix}UserSid"))
    if username and domain:
        return fr"{domain}\{username}", sid
    return username, sid


def _signal_id(
    alert: dict[str, Any],
    source: dict[str, Any],
    system: dict[str, Any],
) -> str:
    value = (
        source.get("id")
        or alert.get("_id")
        or system.get("eventRecordID")
    )
    if value is None or not str(value).strip():
        raise ValueError("Identifiant Wazuh/Windows absent.")
    return str(value)


def _action(access_mask: str | None, access_list: str | None) -> ObservedAction:
    accesses = (access_list or "").casefold()
    try:
        mask = int(access_mask or "0", 16)
    except ValueError:
        mask = 0

    if mask & 0x10000 or "%%1537" in accesses or "delete" in accesses:
        return ObservedAction.DELETE
    if (
        mask & 0x2
        or mask & 0x4
        or "%%4417" in accesses
        or "%%4418" in accesses
        or "writedata" in accesses
        or "appenddata" in accesses
    ):
        return ObservedAction.MODIFY
    if mask & 0x1 or "%%4416" in accesses or "readdata" in accesses:
        return ObservedAction.READ
    return ObservedAction.UNKNOWN


def _base(
    alert: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = _unwrap(alert)
    try:
        win = source["data"]["win"]
        system = win["system"]
        event = win["eventdata"]
    except (KeyError, TypeError) as error:
        raise ValueError("Événement Windows Wazuh invalide.") from error
    return source, system, event, source.get("agent") or {}


def parse_windows_signal(alert: dict[str, Any]) -> SecuritySignal:
    """Convertit 4663, 4624, 5145, 4688 et Sysmon en signal commun."""

    source, system, event, agent = _base(alert)
    event_id = str(system.get("eventID") or "")
    provider = str(system.get("providerName") or "").casefold()
    timestamp = _parse_timestamp(str(source["timestamp"]))
    hostname = _clean(system.get("computer")) or _clean(agent.get("name"))
    agent_id = _clean(agent.get("id"))
    signal_id = _signal_id(alert, source, system)
    record_id = _clean(system.get("eventRecordID"))

    if _SYSMON_PROVIDER in provider:
        return _parse_sysmon(
            event_id=event_id,
            event=event,
            signal_id=signal_id,
            timestamp=timestamp,
            hostname=hostname,
            agent_id=agent_id,
            record_id=record_id,
        )

    if event_id == "4663":
        user, sid = _user(event, "subject")
        access_mask = _clean(event.get("accessMask"))
        access_list = _clean(event.get("accessList") or event.get("accesses"))
        action = _action(access_mask, access_list)
        tags = ["windows", "file", f"action:{action.value}"]
        process = _clean(event.get("processName"))
        if process and process.casefold().endswith(("winword.exe", "excel.exe")):
            tags.append("office_open_candidate")
        return SecuritySignal(
            signal_id=signal_id,
            kind=SignalKind.FILE_ACCESS,
            observed_at=timestamp,
            source="wazuh:windows:4663",
            platform="windows",
            confidence=EvidenceConfidence.DIRECT,
            action=action,
            agent_id=agent_id,
            hostname=hostname,
            user=user,
            user_sid=sid,
            logon_id=_clean(event.get("subjectLogonId")),
            process_name=process,
            process_id=_clean(event.get("processId")),
            file_path=_clean(event.get("objectName")),
            evidence_event_id=record_id,
            tags=tuple(tags),
            raw_fields=dict(event),
        )

    if event_id == "4624":
        user, sid = _user(event, "target")
        logon_type = _clean(event.get("logonType")) or "unknown"
        entry = _LOGON_TYPES.get(logon_type, "unknown")
        source_ip = _clean(event.get("ipAddress"))
        return SecuritySignal(
            signal_id=signal_id,
            kind=SignalKind.LOGON,
            observed_at=timestamp,
            source="wazuh:windows:4624",
            platform="windows",
            confidence=(
                EvidenceConfidence.HIGH
                if source_ip
                else EvidenceConfidence.MEDIUM
            ),
            action=ObservedAction.LOGON,
            agent_id=agent_id,
            hostname=hostname,
            user=user,
            user_sid=sid,
            logon_id=_clean(event.get("targetLogonId")),
            logon_type=logon_type,
            entry_channel=entry,
            source_ip=source_ip,
            source_port=_clean(event.get("ipPort")),
            process_name=_clean(event.get("processName")),
            process_id=_clean(event.get("processId")),
            evidence_event_id=record_id,
            tags=("windows", "logon", f"logon_type:{logon_type}", f"entry:{entry}"),
            raw_fields=dict(event),
        )

    if event_id == "5145":
        user, sid = _user(event, "subject")
        access_mask = _clean(event.get("accessMask"))
        access_list = _clean(event.get("accessList") or event.get("accesses"))
        action = _action(access_mask, access_list)
        return SecuritySignal(
            signal_id=signal_id,
            kind=SignalKind.REMOTE_FILE_ACCESS,
            observed_at=timestamp,
            source="wazuh:windows:5145",
            platform="windows",
            confidence=EvidenceConfidence.DIRECT,
            action=action,
            agent_id=agent_id,
            hostname=hostname,
            user=user,
            user_sid=sid,
            logon_id=_clean(event.get("subjectLogonId")),
            source_ip=_clean(event.get("ipAddress")),
            source_port=_clean(event.get("ipPort")),
            file_path=_clean(event.get("relativeTargetName")),
            evidence_event_id=record_id,
            tags=("windows", "smb", "remote_file", f"action:{action.value}"),
            raw_fields=dict(event),
        )

    if event_id == "4688":
        user, sid = _user(event, "target")
        if not user:
            user, sid = _user(event, "subject")
        return SecuritySignal(
            signal_id=signal_id,
            kind=SignalKind.PROCESS_EXECUTION,
            observed_at=timestamp,
            source="wazuh:windows:4688",
            platform="windows",
            confidence=EvidenceConfidence.DIRECT,
            action=ObservedAction.EXECUTE,
            agent_id=agent_id,
            hostname=hostname,
            user=user,
            user_sid=sid,
            logon_id=(
                _clean(event.get("targetLogonId"))
                or _clean(event.get("subjectLogonId"))
            ),
            process_name=_clean(event.get("newProcessName")),
            process_id=_clean(event.get("newProcessId")),
            parent_process_name=(
                _clean(event.get("parentProcessName"))
                or _clean(event.get("creatorProcessName"))
            ),
            parent_process_id=_clean(event.get("processId")),
            command_line=_clean(event.get("commandLine")),
            evidence_event_id=record_id,
            tags=("windows", "process", "command"),
            raw_fields=dict(event),
        )

    raise ValueError(f"Événement Windows non pris en charge : {event_id}.")


def _parse_sysmon(
    *,
    event_id: str,
    event: dict[str, Any],
    signal_id: str,
    timestamp: datetime,
    hostname: str | None,
    agent_id: str | None,
    record_id: str | None,
) -> SecuritySignal:
    common = {
        "signal_id": signal_id,
        "observed_at": timestamp,
        "platform": "windows",
        "confidence": EvidenceConfidence.DIRECT,
        "agent_id": agent_id,
        "hostname": hostname,
        "user": _clean(event.get("user")),
        "process_name": _clean(event.get("image")),
        "process_id": _clean(event.get("processId")),
        "process_guid": _clean(event.get("processGuid")),
        "evidence_event_id": record_id,
        "raw_fields": dict(event),
    }
    if event_id == "1":
        return SecuritySignal(
            **common,
            kind=SignalKind.PROCESS_EXECUTION,
            source="wazuh:sysmon:1",
            action=ObservedAction.EXECUTE,
            parent_process_name=_clean(event.get("parentImage")),
            parent_process_id=_clean(event.get("parentProcessId")),
            command_line=_clean(event.get("commandLine")),
            tags=("windows", "sysmon", "process", "command"),
        )
    if event_id == "3":
        return SecuritySignal(
            **common,
            kind=SignalKind.NETWORK_CONNECTION,
            source="wazuh:sysmon:3",
            action=ObservedAction.CONNECT,
            source_ip=_clean(event.get("sourceIp")),
            source_port=_clean(event.get("sourcePort")),
            destination_ip=_clean(event.get("destinationIp")),
            destination_port=_clean(event.get("destinationPort")),
            tags=("windows", "sysmon", "network"),
        )
    if event_id in {"11", "23", "26"}:
        deleted = event_id in {"23", "26"}
        return SecuritySignal(
            **common,
            kind=SignalKind.FILE_CHANGE,
            source=f"wazuh:sysmon:{event_id}",
            action=(ObservedAction.DELETE if deleted else ObservedAction.CREATE),
            file_path=_clean(event.get("targetFilename")),
            tags=(
                "windows",
                "sysmon",
                "file_delete" if deleted else "file_create",
            ),
        )
    if event_id == "22":
        return SecuritySignal(
            **common,
            kind=SignalKind.DNS_QUERY,
            source="wazuh:sysmon:22",
            action=ObservedAction.UNKNOWN,
            query_name=_clean(event.get("queryName")),
            tags=("windows", "sysmon", "dns"),
        )
    raise ValueError(f"Événement Sysmon non pris en charge : {event_id}.")
