# src/domain/verdict.py

from dataclasses import dataclass


@dataclass(slots=True)
class DetectionVerdict:
    level: str
    confidence: float
    reasons: tuple[str, ...]
    event_id: str
    decoy_instance_id: str