"""Pipeline vertical Wazuh vers verdict JANUS."""

import ntpath
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from ..correlation.engine import correlate_event
from ..domain.models import (
    DecoyInstance,
    DetectionVerdict,
    EventAction,
    SecurityEvent,
)
from ..telemetry.wazuh_adapter import parse_wazuh_event
from ..verdict.engine import build_verdict


class ActiveDecoyRegistry(Protocol):
    """Contrat minimal partagé par les registres mémoire et SQLite."""

    def list_active(self) -> list[DecoyInstance]: ...


@dataclass(frozen=True)
class DetectionAnalysis:
    """Résultat complet, y compris lorsqu'aucun leurre n'est reconnu."""

    event: SecurityEvent
    decoy: DecoyInstance | None
    verdict: DetectionVerdict | None
    suppressed: bool = False
    suppression_reason: str | None = None

    @property
    def detected(self) -> bool:
        return (
            not self.suppressed
            and self.decoy is not None
            and self.verdict is not None
        )


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _same_windows_executable(first: str, second: str) -> bool:
    return ntpath.normcase(ntpath.normpath(first)) == ntpath.normcase(
        ntpath.normpath(second)
    )


def _trusted_deployment_reason(
    event: SecurityEvent,
    decoy: DecoyInstance,
    trusted_process_path: str | None,
    deployment_grace_seconds: float,
) -> str | None:
    """Ignore uniquement les écritures du générateur juste après le dépôt."""

    if (
        deployment_grace_seconds <= 0
        or not trusted_process_path
        or not event.process_name
        or not decoy.created_at
        or event.action is not EventAction.MODIFY
        or not _same_windows_executable(event.process_name, trusted_process_path)
    ):
        return None

    age_seconds = (
        _aware_utc(event.timestamp) - _aware_utc(decoy.created_at)
    ).total_seconds()
    if -5 <= age_seconds <= deployment_grace_seconds:
        return (
            "Écriture effectuée par le processus de déploiement JANUS "
            f"{age_seconds:.1f} s après l'enregistrement du leurre."
        )
    return None


def analyze_wazuh_alert(
    alert: dict[str, Any],
    registry: ActiveDecoyRegistry,
    *,
    trusted_process_path: str | None = None,
    deployment_grace_seconds: float = 0,
) -> DetectionAnalysis:
    """Normalise, corrèle et évalue une alerte Wazuh 4663.

    Une alerte portant sur un fichier non enregistré reste une preuve Wazuh,
    mais ne devient pas une détection JANUS. Cette séparation empêche qu'un
    fichier ordinaire du dossier surveillé soit pris pour un honeydocument.
    """

    event = parse_wazuh_event(alert)
    decoy = correlate_event(event, registry.list_active())
    suppression_reason = (
        _trusted_deployment_reason(
            event,
            decoy,
            trusted_process_path,
            deployment_grace_seconds,
        )
        if decoy is not None
        else None
    )
    if suppression_reason:
        return DetectionAnalysis(
            event=event,
            decoy=decoy,
            verdict=None,
            suppressed=True,
            suppression_reason=suppression_reason,
        )

    verdict = build_verdict(event, decoy) if decoy is not None else None

    return DetectionAnalysis(
        event=event,
        decoy=decoy,
        verdict=verdict,
    )
