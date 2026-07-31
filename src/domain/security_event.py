# src/domain/security_event.py

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class SecurityEvent:
    event_id: str
    source: str
    timestamp: datetime
    hostname: str
    action: str
    username: str | None = None
    process_name: str | None = None
    file_path: str | None = None
    source_ip: str | None = None
    raw_event: dict[str, Any] = field(default_factory=dict)