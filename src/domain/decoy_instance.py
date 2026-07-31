# src/domain/decoy_instance.py

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class DecoyInstance:
    instance_id: str
    campaign_id: str
    decoy_type: str
    deployed_path: str
    created_at: datetime
    expires_at: datetime
    expected_hostname: str | None = None
    expected_users: tuple[str, ...] = ()
    status: str = "active"