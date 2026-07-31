"""Point d'entrée commun des adaptateurs de télémétrie JANUS."""

from __future__ import annotations

from typing import Any

from ..domain.signals import SecuritySignal
from .linux_audit_adapter import parse_linux_audit_signal
from .windows_signal_adapter import parse_windows_signal


def parse_wazuh_signal(alert: dict[str, Any]) -> SecuritySignal:
    source = alert.get("_source")
    if not isinstance(source, dict):
        source = alert
    data = source.get("data") or {}
    if isinstance(data.get("win"), dict):
        return parse_windows_signal(alert)
    if isinstance(data.get("audit"), dict):
        return parse_linux_audit_signal(alert)
    raise ValueError("Type de télémétrie Wazuh non pris en charge.")
