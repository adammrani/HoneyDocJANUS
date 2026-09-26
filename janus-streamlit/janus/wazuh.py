"""Normalisation prudente Wazuh/Windows et collecteur Indexer facultatif."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import PureWindowsPath
from typing import Any, Callable

import requests
from requests.auth import HTTPBasicAuth

from .config import Settings
from .models import NormalizedSignal


SUPPORTED_WINDOWS_EVENTS = {"4624", "4663", "4688", "5145"}
SUPPORTED_SYSMON_EVENTS = {"1", "3", "11", "22", "23", "26"}


def _unwrap(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("_source")
    return source if isinstance(source, dict) else alert


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text


def _user(event: dict[str, Any], prefix: str) -> str | None:
    username = _clean(event.get(f"{prefix}UserName"))
    domain = _clean(event.get(f"{prefix}DomainName"))
    return f"{domain}\\{username}" if username and domain else username


def _event_sections(alert: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = _unwrap(alert)
    try:
        win = source["data"]["win"]
        system = win["system"]
        event = win.get("eventdata") or {}
    except (KeyError, TypeError) as exc:
        raise ValueError("Événement Wazuh Windows invalide.") from exc
    if not isinstance(system, dict) or not isinstance(event, dict):
        raise ValueError("Sections Windows Wazuh invalides.")
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    return source, system, event, agent


def _event_id(alert: dict[str, Any], source: dict[str, Any], system: dict[str, Any]) -> str | None:
    return _clean(source.get("id") or alert.get("_id") or system.get("eventRecordID"))


def _action(event: dict[str, Any]) -> str:
    access_text = str(event.get("accessList") or event.get("accesses") or "").casefold()
    access_mask = str(event.get("accessMask") or "")
    try:
        mask = int(access_mask, 16) if access_mask else 0
    except ValueError:
        mask = 0
    if mask & 0x10000 or "delete" in access_text or "%%1537" in access_text:
        return "delete"
    if mask & 0x2 or mask & 0x4 or "writedata" in access_text or "appenddata" in access_text:
        return "modify"
    if mask & 0x1 or "readdata" in access_text or "%%4416" in access_text:
        return "read"
    return "unknown"


def normalize_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return str(PureWindowsPath(path)).replace("/", "\\")
    except (TypeError, ValueError):
        return path.replace("/", "\\")


def parse_wazuh_signal(alert: dict[str, Any]) -> NormalizedSignal:
    source, system, event, agent = _event_sections(alert)
    code = str(system.get("eventID") or "")
    provider = str(system.get("providerName") or "").casefold()
    observed_at = _clean(source.get("timestamp") or system.get("systemTime"))
    hostname = _clean(system.get("computer") or agent.get("name"))
    source_event_id = _event_id(alert, source, system)
    is_sysmon = "sysmon" in provider

    if is_sysmon and code in SUPPORTED_SYSMON_EVENTS:
        common = {
            "event_code": f"sysmon:{code}",
            "observed_at": observed_at,
            "source_event_id": source_event_id,
            "hostname": hostname,
            "user_name": _clean(event.get("user")),
            "process_name": _clean(event.get("image")),
            "process_id": _clean(event.get("processId")),
            "process_guid": _clean(event.get("processGuid")),
            "logon_id": _clean(event.get("logonId") or event.get("logonGuid")),
            "raw_fields": dict(event),
        }
        if code == "1":
            return NormalizedSignal(
                source="wazuh",
                kind="process_execution",
                action="execute",
                command_line=_clean(event.get("commandLine")),
                parent_process_name=_clean(event.get("parentImage")),
                **common,
            )
        if code == "3":
            return NormalizedSignal(
                source="wazuh",
                kind="network_connection",
                action="connect",
                source_ip=_clean(event.get("sourceIp")),
                source_port=_clean(event.get("sourcePort")),
                **common,
            )
        if code in {"11", "23", "26"}:
            return NormalizedSignal(
                source="wazuh",
                kind="file_change",
                action="delete" if code in {"23", "26"} else "create",
                file_path=normalize_windows_path(_clean(event.get("targetFilename"))),
                **common,
            )
        return NormalizedSignal(
            source="wazuh",
            kind="dns_query",
            action="query",
            file_path=_clean(event.get("queryName")),
            **common,
        )

    if code == "4663":
        return NormalizedSignal(
            source="wazuh",
            kind="file_access",
            event_code=code,
            observed_at=observed_at,
            source_event_id=source_event_id,
            hostname=hostname,
            user_name=_user(event, "subject"),
            logon_id=_clean(event.get("subjectLogonId")),
            process_name=normalize_windows_path(_clean(event.get("processName"))),
            process_id=_clean(event.get("processId")),
            file_path=normalize_windows_path(_clean(event.get("objectName"))),
            action=_action(event),
            raw_fields=dict(event),
        )
    if code == "4624":
        return NormalizedSignal(
            source="wazuh",
            kind="logon",
            event_code=code,
            observed_at=observed_at,
            source_event_id=source_event_id,
            hostname=hostname,
            user_name=_user(event, "target"),
            logon_id=_clean(event.get("targetLogonId")),
            source_ip=_clean(event.get("ipAddress")),
            source_port=_clean(event.get("ipPort")),
            process_name=_clean(event.get("processName")),
            process_id=_clean(event.get("processId")),
            action="logon",
            raw_fields=dict(event),
        )
    if code == "5145":
        return NormalizedSignal(
            source="wazuh",
            kind="remote_file_access",
            event_code=code,
            observed_at=observed_at,
            source_event_id=source_event_id,
            hostname=hostname,
            user_name=_user(event, "subject"),
            logon_id=_clean(event.get("subjectLogonId")),
            source_ip=_clean(event.get("ipAddress")),
            source_port=_clean(event.get("ipPort")),
            file_path=normalize_windows_path(_clean(event.get("relativeTargetName"))),
            action=_action(event),
            raw_fields=dict(event),
        )
    if code == "4688":
        return NormalizedSignal(
            source="wazuh",
            kind="process_execution",
            event_code=code,
            observed_at=observed_at,
            source_event_id=source_event_id,
            hostname=hostname,
            user_name=_user(event, "target") or _user(event, "subject"),
            logon_id=_clean(event.get("targetLogonId") or event.get("subjectLogonId")),
            process_name=normalize_windows_path(_clean(event.get("newProcessName"))),
            process_id=_clean(event.get("newProcessId")),
            parent_process_name=normalize_windows_path(
                _clean(event.get("parentProcessName") or event.get("creatorProcessName"))
            ),
            command_line=_clean(event.get("commandLine")),
            action="execute",
            raw_fields=dict(event),
        )

    return NormalizedSignal(
        source="wazuh",
        kind="normalization_pending",
        event_code=code or None,
        observed_at=observed_at,
        source_event_id=source_event_id,
        hostname=hostname,
        raw_fields=dict(event),
    )


class WazuhIndexerPoller:
    """Interroge wazuh-alerts-* sans supprimer les événements inconnus."""

    def __init__(
        self,
        settings: Settings,
        ingest: Callable[[dict[str, Any], str], Any],
        *,
        session: requests.Session | None = None,
    ):
        self.settings = settings
        self.ingest = ingest
        self.session = session or requests.Session()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.status: dict[str, Any] = {
            "running": False,
            "last_poll_at": None,
            "last_success_at": None,
            "last_error": None,
            "processed_total": 0,
        }
        self._last_timestamp = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        self._logger = logging.getLogger(__name__)

    def start(self) -> None:
        if not self.settings.wazuh_auto_collect or not self.settings.wazuh_indexer_configured:
            return
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="janus-wazuh-poller", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    def _loop(self) -> None:
        self.status["running"] = True
        try:
            while not self.stop_event.is_set():
                try:
                    self.poll_once()
                except Exception as exc:  # noqa: BLE001 - collecteur résilient
                    self.status["last_error"] = str(exc)
                    self._logger.warning("Collecte Wazuh indisponible : %s", exc)
                self.stop_event.wait(self.settings.wazuh_poll_seconds)
        finally:
            self.status["running"] = False

    def poll_once(self) -> int:
        if not self.settings.wazuh_indexer_configured:
            return 0
        url = (
            f"{self.settings.wazuh_indexer_url.rstrip('/')}/"
            f"{self.settings.wazuh_index_pattern}/_search"
        )
        self.status["last_poll_at"] = datetime.now(UTC).isoformat()
        checkpoint = self._last_timestamp
        newest_timestamp = checkpoint
        search_after: list[Any] | None = None
        count = 0
        while True:
            body: dict[str, Any] = {
                "size": 250,
                "track_total_hits": False,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"timestamp": {"gte": checkpoint}}},
                            {"exists": {"field": "data.win.system.eventID"}},
                        ]
                    }
                },
                "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            }
            if search_after is not None:
                body["search_after"] = search_after

            response = self.session.post(
                url,
                json=body,
                auth=HTTPBasicAuth(
                    str(self.settings.wazuh_indexer_username),
                    str(self.settings.wazuh_indexer_password),
                ),
                verify=self.settings.wazuh_verify_ssl,
                timeout=20,
            )
            response.raise_for_status()
            payload = response.json()
            hits = payload.get("hits", {}).get("hits", [])
            if not isinstance(hits, list):
                raise RuntimeError("Réponse Wazuh Indexer invalide.")
            if not hits:
                break

            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                self.ingest(hit, "verified")
                source = _unwrap(hit)
                if source.get("timestamp"):
                    newest_timestamp = max(newest_timestamp, str(source["timestamp"]))
                count += 1

            if len(hits) < 250:
                break
            last_sort = hits[-1].get("sort") if isinstance(hits[-1], dict) else None
            if not isinstance(last_sort, list) or not last_sort:
                raise RuntimeError(
                    "Pagination Wazuh impossible : la valeur sort est absente."
                )
            search_after = last_sort

        self._last_timestamp = newest_timestamp
        self.status["processed_total"] += count
        self.status["last_success_at"] = datetime.now(UTC).isoformat()
        self.status["last_error"] = None
        return count
