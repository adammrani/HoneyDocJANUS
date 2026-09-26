"""Collecteur automatique Wazuh Indexer vers le pipeline JANUS."""

from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from .pipeline import ActiveDecoyRegistry, analyze_wazuh_alert
from ..registry.security_signal_store import SqliteSecuritySignalStore
from ..registry.wazuh_detection_store import SqliteWazuhDetectionStore
from ..telemetry.signal_adapter import parse_wazuh_signal
from ..telemetry.wazuh_indexer_client import WazuhAlertPage


class WazuhAlertSource(Protocol):
    def fetch_alerts(
        self,
        *,
        rule_id: str,
        rule_ids: tuple[str, ...] = (),
        since_epoch_ms: int,
        until: str,
        batch_size: int,
        search_after: list[Any] | None = None,
    ) -> WazuhAlertPage: ...


@dataclass(frozen=True)
class WazuhCollectorConfig:
    rule_id: str = "100100"
    additional_rule_ids: tuple[str, ...] = ()
    batch_size: int = 200
    initial_lookback_minutes: int = 15
    overlap_seconds: int = 120
    settle_seconds: int = 3
    poll_interval_seconds: float = 5
    deployment_grace_seconds: float = 15
    trusted_process_path: str = sys.executable


class WazuhCollector:
    """Lit, déduplique, corrèle et persiste les alertes Wazuh."""

    def __init__(
        self,
        *,
        source: WazuhAlertSource,
        registry: ActiveDecoyRegistry,
        store: SqliteWazuhDetectionStore,
        evidence_store: SqliteSecuritySignalStore | None = None,
        config: WazuhCollectorConfig,
        clock_epoch_ms: Callable[[], int] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._source = source
        self._registry = registry
        self._store = store
        self._evidence_store = evidence_store
        self._config = config
        self._clock_epoch_ms = clock_epoch_ms or (
            lambda: int(time.time() * 1000)
        )
        self._logger = logger or logging.getLogger(__name__)
        self._status_lock = threading.Lock()
        self._status: dict[str, Any] = {
            "running": False,
            "last_poll_at": None,
            "last_success_at": None,
            "last_error": None,
            "consecutive_errors": 0,
            "processed_total": self._store.count(),
            "last_batch_new": 0,
            "last_batch_matched": 0,
            "last_batch_suppressed": 0,
            "last_batch_evidence_normalized": 0,
            "last_batch_evidence_pending": 0,
            "cursor": self._store.get_cursor(),
        }

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_newer(
        candidate: list[Any],
        current: list[Any] | None,
    ) -> bool:
        if current is None:
            return True
        return (int(candidate[0]), str(candidate[1])) > (
            int(current[0]),
            str(current[1]),
        )

    def _update_status(self, **values: Any) -> None:
        with self._status_lock:
            self._status.update(values)

    def status(self) -> dict[str, Any]:
        with self._status_lock:
            return dict(self._status)

    def _preserve_priority_evidence(self, alert: dict[str, Any]) -> str:
        """Store JANUS-rule evidence immediately, ahead of the broad backlog."""

        if self._evidence_store is None:
            return "disabled"

        evidence_key = self._evidence_store.record_raw(alert)
        try:
            signal = parse_wazuh_signal(alert)
        except ValueError as error:
            self._evidence_store.update_raw_status(
                evidence_key,
                status="normalization_pending",
                error=str(error),
            )
            return "pending"

        self._evidence_store.record(alert, signal)
        return "normalized"

    def run_once(self) -> int:
        """Traite toutes les nouvelles alertes disponibles puis rend la main."""

        now_epoch_ms = self._clock_epoch_ms()
        cursor = self._store.get_cursor()
        if cursor is None:
            since_epoch_ms = now_epoch_ms - (
                self._config.initial_lookback_minutes * 60 * 1000
            )
        else:
            since_epoch_ms = max(
                0,
                int(cursor[0]) - self._config.overlap_seconds * 1000,
            )

        until = (
            f"now-{self._config.settle_seconds}s"
            if self._config.settle_seconds > 0
            else "now"
        )
        search_after: list[Any] | None = None
        highest_cursor = cursor
        new_count = 0
        matched_count = 0
        suppressed_count = 0
        evidence_normalized_count = 0
        evidence_pending_count = 0

        while True:
            page = self._source.fetch_alerts(
                rule_id=self._config.rule_id,
                rule_ids=self._config.additional_rule_ids,
                since_epoch_ms=since_epoch_ms,
                until=until,
                batch_size=self._config.batch_size,
                search_after=search_after,
            )

            for alert in page.alerts:
                evidence_status = self._preserve_priority_evidence(alert)
                evidence_normalized_count += int(evidence_status == "normalized")
                evidence_pending_count += int(evidence_status == "pending")
                try:
                    analysis = analyze_wazuh_alert(
                        alert,
                        self._registry,
                        trusted_process_path=(
                            self._config.trusted_process_path
                        ),
                        deployment_grace_seconds=(
                            self._config.deployment_grace_seconds
                        ),
                    )
                except ValueError as error:
                    self._logger.warning(
                        "Alerte Wazuh ignorée car elle est invalide : %s",
                        error,
                    )
                    continue

                if self._store.record(alert, analysis):
                    new_count += 1
                    matched_count += int(analysis.decoy is not None)
                    suppressed_count += int(analysis.suppressed)

            if page.next_search_after is not None and self._is_newer(
                page.next_search_after,
                highest_cursor,
            ):
                highest_cursor = page.next_search_after
                self._store.set_cursor(highest_cursor)

            if (
                not page.alerts
                or len(page.alerts) < self._config.batch_size
                or page.next_search_after is None
            ):
                break
            search_after = page.next_search_after

        previous_total = int(self.status()["processed_total"])
        self._update_status(
            last_poll_at=self._utc_now(),
            last_success_at=self._utc_now(),
            last_error=None,
            consecutive_errors=0,
            processed_total=previous_total + new_count,
            last_batch_new=new_count,
            last_batch_matched=matched_count,
            last_batch_suppressed=suppressed_count,
            last_batch_evidence_normalized=evidence_normalized_count,
            last_batch_evidence_pending=evidence_pending_count,
            cursor=highest_cursor,
        )
        return new_count

    def run_forever(self, stop_event: threading.Event) -> None:
        self._update_status(running=True)
        try:
            while not stop_event.is_set():
                try:
                    self.run_once()
                except Exception as error:  # noqa: BLE001 - boucle résiliente
                    status = self.status()
                    self._logger.warning(
                        "Collecte Wazuh indisponible : %s",
                        error,
                    )
                    self._update_status(
                        last_poll_at=self._utc_now(),
                        last_error=str(error),
                        consecutive_errors=(
                            int(status["consecutive_errors"]) + 1
                        ),
                        last_batch_new=0,
                        last_batch_matched=0,
                        last_batch_suppressed=0,
                        last_batch_evidence_normalized=0,
                        last_batch_evidence_pending=0,
                    )
                stop_event.wait(self._config.poll_interval_seconds)
        finally:
            self._update_status(running=False)
