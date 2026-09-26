from datetime import datetime
from dataclasses import dataclass
from enum import Enum

class DecoyStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"

class EventAction(str, Enum):
    READ = "read"
    COPY = "copy"
    MODIFY = "modify"
    DELETE = "delete"
    UNKNOWN = "unknown"

class VerdictLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    SUSPECT = "suspect"
    CRITICAL = "critical"

@dataclass(frozen=True)
class DecoyInstance:
    instance_id: str
    filename: str
    deployment_path: str
    expected_hostname: str | None
    expected_user: str | None
    status: DecoyStatus = DecoyStatus.ACTIVE
    created_at: datetime | None = None

@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    hostname: str
    user: str
    path: str
    action: EventAction
    timestamp: datetime
    source: str = "simulated"
    process_name: str | None = None
    process_id: str | None = None
    access_mask: str | None = None
    agent_id: str | None = None
    event_record_id: str | None = None

@dataclass(frozen=True)
class DetectionVerdict:
    level: VerdictLevel
    score: int
    reasons: list[str]
    decoy_instance_id: str
    event_id: str
