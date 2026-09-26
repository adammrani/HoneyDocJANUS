"""Objets publics et vocabulaires de preuve de JANUS."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SensorMode(StrEnum):
    LOCAL_PIXEL = "local_pixel"
    CANARY_REMOTE = "canary_remote"
    DUAL = "dual"
    CANARY_OFFICIAL = "canary_official"


class EvidenceCategory(StrEnum):
    OBSERVED = "observed"
    REPORTED = "reported"
    CONTROLLED = "controlled"
    INFERRED = "inferred"


class EvidenceStrength(StrEnum):
    CONFIRMED = "confirmed"
    CORROBORATED = "corroborated"
    CANDIDATE = "candidate"
    UNSUPPORTED = "unsupported"


class TransportTrust(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INVALID = "invalid"


class GenerateRequest(BaseModel):
    campaign: str = Field(default="Revue finance et opérations", min_length=2, max_length=120)
    objective: str = Field(
        default="Détecter un accès non prévu à un document synthétique de laboratoire",
        min_length=4,
        max_length=300,
    )
    theme: str = Field(default="Prévisions consolidées T4 2026", min_length=2, max_length=180)
    department: str = Field(default="Direction financière", min_length=2, max_length=120)
    audience: str = Field(default="Comité de pilotage", min_length=2, max_length=120)
    sensitivity: str = Field(default="Restreinte", min_length=2, max_length=60)
    sensor_mode: SensorMode = SensorMode.LOCAL_PIXEL
    canary_url: str | None = Field(default=None, max_length=2048)

    @field_validator("campaign", "objective", "theme", "department", "audience", "sensitivity")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


@dataclass(frozen=True)
class GeneratedContent:
    title: str
    body: str
    generator_mode: str


@dataclass(frozen=True)
class Beacon:
    relationship_id: str
    url: str
    label: str


@dataclass(frozen=True)
class NormalizedSignal:
    source: str
    kind: str
    event_code: str | None
    observed_at: str | None
    source_event_id: str | None
    hostname: str | None = None
    user_name: str | None = None
    logon_id: str | None = None
    source_ip: str | None = None
    source_port: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    process_guid: str | None = None
    command_line: str | None = None
    parent_process_name: str | None = None
    file_path: str | None = None
    user_agent: str | None = None
    action: str | None = None
    raw_fields: dict[str, Any] | None = None

