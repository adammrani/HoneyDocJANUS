"""Modèle commun pour les preuves collectées par JANUS.

Un ``SecuritySignal`` représente une observation, pas une conclusion. Les
champs ``confidence`` et ``tags`` empêchent notamment de présenter un
User-Agent, une géolocalisation ou une action reconstruite comme une certitude.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SignalKind(str, Enum):
    FILE_ACCESS = "file_access"
    REMOTE_FILE_ACCESS = "remote_file_access"
    FILE_CHANGE = "file_change"
    LOGON = "logon"
    PROCESS_EXECUTION = "process_execution"
    COMMAND_EXECUTION = "command_execution"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    TOKEN_TRIGGER = "token_trigger"
    HONEYPOT_SESSION = "honeypot_session"


class ObservedAction(str, Enum):
    READ = "read"
    MODIFY = "modify"
    DELETE = "delete"
    CREATE = "create"
    EXECUTE = "execute"
    CONNECT = "connect"
    LOGON = "logon"
    UNKNOWN = "unknown"


class EvidenceConfidence(str, Enum):
    DIRECT = "direct"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SecuritySignal:
    signal_id: str
    kind: SignalKind
    observed_at: datetime
    source: str
    platform: str
    confidence: EvidenceConfidence
    action: ObservedAction = ObservedAction.UNKNOWN
    agent_id: str | None = None
    hostname: str | None = None
    user: str | None = None
    user_sid: str | None = None
    logon_id: str | None = None
    logon_type: str | None = None
    entry_channel: str | None = None
    source_ip: str | None = None
    source_port: str | None = None
    destination_ip: str | None = None
    destination_port: str | None = None
    user_agent: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    process_guid: str | None = None
    parent_process_name: str | None = None
    parent_process_id: str | None = None
    command_line: str | None = None
    working_directory: str | None = None
    terminal: str | None = None
    audit_user_id: str | None = None
    effective_user_id: str | None = None
    file_path: str | None = None
    query_name: str | None = None
    token_id: str | None = None
    evidence_event_id: str | None = None
    tags: tuple[str, ...] = ()
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Retourne une représentation JSON-sérialisable."""

        value = asdict(self)
        value["kind"] = self.kind.value
        value["action"] = self.action.value
        value["confidence"] = self.confidence.value
        value["observed_at"] = self.observed_at.isoformat()
        value["tags"] = list(self.tags)
        return value
