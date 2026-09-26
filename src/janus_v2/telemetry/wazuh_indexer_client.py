"""Client HTTP minimal pour lire les alertes depuis Wazuh Indexer."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


class WazuhIndexerError(RuntimeError):
    """Erreur de connexion ou de réponse de Wazuh Indexer."""


@dataclass(frozen=True)
class WazuhAlertPage:
    alerts: list[dict[str, Any]]
    next_search_after: list[Any] | None


JsonTransport = Callable[[urllib.request.Request, ssl.SSLContext, float], dict]


def _default_transport(
    request: urllib.request.Request,
    context: ssl.SSLContext,
    timeout: float,
) -> dict:
    with urllib.request.urlopen(
        request,
        context=context,
        timeout=timeout,
    ) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise WazuhIndexerError("Réponse JSON Indexer invalide.")
    return payload


class WazuhIndexerClient:
    """Interroge les documents Wazuh d'une règle avec pagination stable."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        index_pattern: str = "wazuh-alerts-4.x-*",
        verify_ssl: bool = True,
        ca_cert_path: str | None = None,
        timeout_seconds: float = 10,
        transport: JsonTransport | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("L'URL Wazuh Indexer est obligatoire.")
        if not username or not password:
            raise ValueError("Les identifiants Wazuh Indexer sont obligatoires.")

        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._index_pattern = index_pattern
        self._timeout_seconds = timeout_seconds
        self._transport = transport or _default_transport

        if verify_ssl:
            self._ssl_context = ssl.create_default_context(
                cafile=ca_cert_path or None
            )
        else:
            self._ssl_context = ssl._create_unverified_context()

    def fetch_alerts(
        self,
        *,
        rule_id: str,
        rule_ids: tuple[str, ...] = (),
        since_epoch_ms: int,
        until: str,
        batch_size: int,
        search_after: list[Any] | None = None,
    ) -> WazuhAlertPage:
        """Retourne une page chronologique d'alertes de la règle demandée."""

        selected_rule_ids = tuple(dict.fromkeys((rule_id, *rule_ids)))
        rule_filter: dict[str, Any] = (
            {"term": {"rule.id": rule_id}}
            if len(selected_rule_ids) == 1
            else {"terms": {"rule.id": list(selected_rule_ids)}}
        )
        body: dict[str, Any] = {
            "size": batch_size,
            "query": {
                "bool": {
                    "filter": [
                        rule_filter,
                        {
                            "range": {
                                "timestamp": {
                                    "gte": since_epoch_ms,
                                    "lte": until,
                                    "format": "epoch_millis||strict_date_optional_time",
                                }
                            }
                        },
                    ]
                }
            },
            "sort": [
                {"timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": {"order": "asc"}},
            ],
        }
        if search_after is not None:
            body["search_after"] = search_after

        return self._execute_search(body)

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
    ) -> WazuhAlertPage:
        """Lit les événements Windows/Sysmon et Linux auditd utiles à JANUS."""

        should: list[dict[str, Any]] = []
        if windows_event_ids:
            should.append(
                {"terms": {"data.win.system.eventID": list(windows_event_ids)}}
            )
        if audit_keys:
            should.append({"terms": {"data.audit.key": list(audit_keys)}})
        if not should:
            raise ValueError("Au moins un ID Windows ou une clé auditd est requis.")

        filters: list[dict[str, Any]] = [
            {
                "range": {
                    "timestamp": {
                        "gte": since_epoch_ms,
                        "lte": until,
                        "format": "epoch_millis||strict_date_optional_time",
                    }
                }
            }
        ]
        if agent_ids:
            filters.append({"terms": {"agent.id": list(agent_ids)}})

        body: dict[str, Any] = {
            "size": batch_size,
            "query": {
                "bool": {
                    "filter": filters,
                    "should": should,
                    "minimum_should_match": 1,
                }
            },
            "sort": [
                {"timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": {"order": "asc"}},
            ],
        }
        if search_after is not None:
            body["search_after"] = search_after
        return self._execute_search(body)

    def _execute_search(self, body: dict[str, Any]) -> WazuhAlertPage:
        """Exécute une recherche Indexer et valide sa pagination."""

        index_path = urllib.parse.quote(self._index_pattern, safe="*-._")
        url = f"{self._base_url}/{index_path}/_search"
        credentials = base64.b64encode(
            f"{self._username}:{self._password}".encode("utf-8")
        ).decode("ascii")
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            payload = self._transport(
                request,
                self._ssl_context,
                self._timeout_seconds,
            )
            hits = payload["hits"]["hits"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise WazuhIndexerError(
                "La réponse de Wazuh Indexer ne contient pas les résultats attendus."
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise WazuhIndexerError(
                f"Connexion à Wazuh Indexer impossible : {error}"
            ) from error

        if not isinstance(hits, list) or any(
            not isinstance(hit, dict) for hit in hits
        ):
            raise WazuhIndexerError("Liste de résultats Indexer invalide.")

        next_search_after: list[Any] | None = None
        if hits:
            sort_values = hits[-1].get("sort")
            if not isinstance(sort_values, list) or len(sort_values) < 2:
                raise WazuhIndexerError(
                    "Wazuh Indexer n'a pas renvoyé de curseur de pagination."
                )
            next_search_after = sort_values

        return WazuhAlertPage(
            alerts=hits,
            next_search_after=next_search_after,
        )
