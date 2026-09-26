"""Shared SQLite runtime policy for concurrent JANUS collectors."""

from __future__ import annotations

import threading


# Wazuh and forensic collection run in separate threads while writing to one
# SQLite database. The lock prevents a retry storm when retention owns the
# database's single-writer slot.
COLLECTOR_WRITE_LOCK = threading.RLock()

SQLITE_TIMEOUT_SECONDS = 60
SQLITE_BUSY_TIMEOUT_MS = SQLITE_TIMEOUT_SECONDS * 1000

