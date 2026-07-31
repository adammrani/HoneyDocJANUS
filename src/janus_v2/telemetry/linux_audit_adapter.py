"""Conversion des événements Linux auditd/execve reçus par Wazuh."""

from __future__ import annotations

import os
import shlex
from datetime import datetime
from typing import Any

from ..domain.signals import (
    EvidenceConfidence,
    ObservedAction,
    SecuritySignal,
    SignalKind,
)


_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "fish"}


def _unwrap(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("_source")
    return source if isinstance(source, dict) else alert


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    if len(value) >= 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = f"{value[:-2]}:{value[-2:]}"
    return datetime.fromisoformat(value)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _decode_argument(value: Any) -> str:
    text = str(value)
    if len(text) >= 2 and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode("utf-8")
            if decoded.isprintable():
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return text


def _command_line(audit: dict[str, Any]) -> str | None:
    execve = audit.get("execve")
    arguments: list[tuple[int, str]] = []
    if isinstance(execve, dict):
        for key, value in execve.items():
            if key.startswith("a") and key[1:].isdigit():
                arguments.append((int(key[1:]), _decode_argument(value)))
    if arguments:
        return shlex.join(value for _, value in sorted(arguments))

    command = _clean(audit.get("command"))
    return command


def parse_linux_audit_signal(alert: dict[str, Any]) -> SecuritySignal:
    """Convertit un syscall ``execve`` auditd en commande JANUS.

    auditd voit le lancement du shell et des programmes externes. Les commandes
    internes telles que ``cd`` ou ``export`` ne déclenchent pas forcément
    ``execve`` et ne doivent donc pas être annoncées comme capturées.
    """

    source = _unwrap(alert)
    try:
        audit = source["data"]["audit"]
        timestamp = _parse_timestamp(str(source["timestamp"]))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Événement Linux auditd Wazuh invalide.") from error

    syscall = str(audit.get("syscall") or "").casefold()
    audit_type = str(audit.get("type") or "").casefold()
    key = str(audit.get("key") or "")
    if syscall not in {"59", "execve", "221"} and audit_type != "execve":
        raise ValueError("L'événement auditd n'est pas une exécution execve.")

    agent = source.get("agent") or {}
    signal_id = str(
        source.get("id")
        or alert.get("_id")
        or audit.get("id")
        or ""
    )
    if not signal_id:
        raise ValueError("Identifiant Wazuh/auditd absent.")

    exe = _clean(audit.get("exe"))
    command = _clean(audit.get("command"))
    executable_name = os.path.basename(exe or command or "").casefold()
    tags = ["linux", "auditd", "command", "execve"]
    if executable_name in _SHELLS:
        tags.extend(("shell", f"shell:{executable_name}"))
    if key:
        tags.append(f"audit_key:{key}")

    auid = _clean(audit.get("auid"))
    uid = _clean(audit.get("uid"))
    user = f"auid:{auid}" if auid else (f"uid:{uid}" if uid else None)
    raw_fields = dict(audit)
    raw_fields["cwd"] = audit.get("cwd")

    return SecuritySignal(
        signal_id=signal_id,
        kind=SignalKind.COMMAND_EXECUTION,
        observed_at=timestamp,
        source="wazuh:linux:auditd:execve",
        platform="linux",
        confidence=EvidenceConfidence.DIRECT,
        action=ObservedAction.EXECUTE,
        agent_id=_clean(agent.get("id")),
        hostname=_clean(agent.get("name")),
        user=user,
        logon_id=_clean(audit.get("session")),
        entry_channel="linux_session",
        process_name=exe or command,
        process_id=_clean(audit.get("pid")),
        parent_process_id=_clean(audit.get("ppid")),
        command_line=_command_line(audit),
        working_directory=_clean(audit.get("cwd")),
        terminal=_clean(audit.get("tty")),
        audit_user_id=auid,
        effective_user_id=_clean(audit.get("euid")) or uid,
        evidence_event_id=_clean(audit.get("id")),
        tags=tuple(tags),
        raw_fields=raw_fields,
    )
