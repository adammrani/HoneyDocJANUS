"""Collecteur Wazuh des preuves Windows, Sysmon et Linux auditd."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from ..registry.security_signal_store import SqliteSecuritySignalStore
from ..domain.signals import SignalKind
from ..telemetry.signal_adapter import parse_wazuh_signal
from ..telemetry.wazuh_indexer_client import WazuhAlertPage


class ForensicAlertSource(Protocol):
    def fetch_forensic_signals(
        self,
        *,
        windows_event_ids: tuple[str, ...],
        audit_keys: tuple[str, ...],
        agent_ids: tuple[str, ...],
        since_epoch_ms: int,
        until: str,
        batch_size: int,
        search_after: list[Any] | None = None,
    ) -> WazuhAlertPage: ...


@dataclass(frozen=True)
class ForensicCollectorConfig:
    windows_event_ids: tuple[str, ...] = (
        "4624", "4663", "4688", "5145", "1", "3", "11", "22", "23", "26"
    )
    audit_keys: tuple[str, ...] = ("audit-wazuh-c", "janus-command")
    agent_ids: tuple[str, ...] = ()
    accepted_logon_types: tuple[str, ...] = (
        "2", "3", "8", "9", "10", "11", "12", "13"
    )
    batch_size: int = 200
    initial_lookback_minutes: int = 15
    overlap_seconds: int = 120
    settle_seconds: int = 3
    poll_interval_seconds: float = 5


class ForensicCollector:
    """Normalise, déduplique et persiste les observations forensiques."""

    def __init__(
        self,
        *,
        source: ForensicAlertSource,
        store: SqliteSecuritySignalStore,
        config: ForensicCollectorConfig,
        clock_epoch_ms: Callable[[], int] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._source = source
        self._store = store
        self._config = config
        self._clock_epoch_ms = clock_epoch_ms or (lambda: int(time.time() * 1000))
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
            "last_batch_windows": 0,
            "last_batch_linux": 0,
            "last_batch_ignored": 0,
            "cursor": self._store.get_cursor(),
        }

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_newer(candidate: list[Any], current: list[Any] | None) -> bool:
        if current is None:
            return True
        return (int(candidate[0]), str(candidate[1])) > (
            int(current[0]), str(current[1])
        )

    def _update_status(self, **values: Any) -> None:
        with self._status_lock:
            self._status.update(values)

    def status(self) -> dict[str, Any]:
        with self._status_lock:
            return dict(self._status)

    def run_once(self) -> int:
        now_epoch_ms = self._clock_epoch_ms()
        cursor = self._store.get_cursor()
        since_epoch_ms = (
            now_epoch_ms - self._config.initial_lookback_minutes * 60 * 1000
            if cursor is None
            else max(0, int(cursor[0]) - self._config.overlap_seconds * 1000)
        )
        until = (
            f"now-{self._config.settle_seconds}s"
            if self._config.settle_seconds > 0 else "now"
        )
        search_after: list[Any] | None = None
        highest_cursor = cursor
        new_count = windows_count = linux_count = ignored_count = 0

        while True:
            page = self._source.fetch_forensic_signals(
                windows_event_ids=self._config.windows_event_ids,
                audit_keys=self._config.audit_keys,
                agent_ids=self._config.agent_ids,
                since_epoch_ms=since_epoch_ms,
                until=until,
                batch_size=self._config.batch_size,
                search_after=search_after,
            )
            for alert in page.alerts:
                try:
                    signal = parse_wazuh_signal(alert)
                except ValueError as error:
                    self._logger.debug("Signal Wazuh ignoré : %s", error)
                    continue
                if (
                    signal.kind is SignalKind.LOGON
                    and signal.logon_type not in self._config.accepted_logon_types
                ):
                    ignored_count += 1
                    continue
                if self._store.record(alert, signal):
                    new_count += 1
                    windows_count += int(signal.platform == "windows")
                    linux_count += int(signal.platform == "linux")

            if page.next_search_after is not None and self._is_newer(
                page.next_search_after, highest_cursor
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

        self._update_status(
            last_poll_at=self._utc_now(),
            last_success_at=self._utc_now(),
            last_error=None,
            consecutive_errors=0,
            processed_total=self._store.count(),
            last_batch_new=new_count,
            last_batch_windows=windows_count,
            last_batch_linux=linux_count,
            last_batch_ignored=ignored_count,
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
                    self._logger.warning("Collecte forensique indisponible : %s", error)
                    self._update_status(
                        last_poll_at=self._utc_now(),
                        last_error=str(error),
                        consecutive_errors=int(status["consecutive_errors"]) + 1,
                        last_batch_new=0,
                        last_batch_windows=0,
                        last_batch_linux=0,
                        last_batch_ignored=0,
                    )
                stop_event.wait(self._config.poll_interval_seconds)
        finally:
            self._update_status(running=False)
