"""Cas d'usage JANUS : génération, réception brute, normalisation et corrélation."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from .ai import ContentGenerator
from .canary import (
    CanaryError,
    CanarytokensClient,
    TokenCredentials,
    extract_history_hits,
)
from .config import Settings
from .database import Database, utc_now
from .documents import build_honeydocx, safe_filename, sha256
from .models import (
    Beacon,
    EvidenceCategory,
    EvidenceStrength,
    GenerateRequest,
    SensorMode,
    TransportTrust,
)
from .wazuh import normalize_windows_path, parse_wazuh_signal


class JanusError(RuntimeError):
    pass


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class JanusService:
    def __init__(
        self,
        settings: Settings,
        *,
        database: Database | None = None,
        content_generator: ContentGenerator | None = None,
        canary_client: CanarytokensClient | None = None,
    ):
        self.settings = settings
        self.settings.ensure_directories()
        self.database = database or Database(settings.database_path)
        self.database.initialize()
        self.content_generator = content_generator or ContentGenerator(settings)
        self.canary_client = canary_client or CanarytokensClient(settings)
        self.wazuh_poller_status: dict[str, Any] | None = None

    def generate(self, request: GenerateRequest) -> dict[str, Any]:
        content = self.content_generator.generate(request.theme, "docx")
        local_token: str | None = None
        canary_url: str | None = None
        canary_provider: str | None = None
        credentials: TokenCredentials | None = None
        secrets_row: dict[str, str | None] | None = None

        if request.sensor_mode in {SensorMode.LOCAL_PIXEL, SensorMode.DUAL}:
            local_token = new_id("pxl")
        if request.sensor_mode in {SensorMode.CANARY_REMOTE, SensorMode.DUAL}:
            canary_url = self._validate_remote_canary_url(request.canary_url)

        artifact_id = new_id("art")
        campaign_id = new_id("cmp")
        beacons: list[Beacon] = []
        if local_token:
            beacons.append(
                Beacon(
                    relationship_id="rIdJanusPixel",
                    url=f"{self.settings.public_base_url}/api/pixel/{local_token}",
                    label="Capteur HTTP local JANUS",
                )
            )
        if canary_url:
            beacons.append(
                Beacon(
                    relationship_id="rIdCanaryRemote",
                    url=canary_url,
                    label="Canarytoken HTTP distant",
                )
            )

        if request.sensor_mode == SensorMode.CANARY_OFFICIAL:
            memo = f"JANUS | {request.campaign} | {artifact_id}"
            credentials = self.canary_client.create_word_token(memo, content.body)
            file_bytes = self.canary_client.download_word(credentials)
            canary_url = credentials.token_url or None
            canary_provider = "canarytokens_official_v3_compat"
            secrets_row = {
                "provider_token": credentials.token,
                "provider_auth_token": credentials.auth_token,
                "provider_hostname": credentials.hostname,
            }
            content_mode = f"{content.generator_mode}+provider-official"
        else:
            file_bytes = build_honeydocx(
                artifact_id=artifact_id,
                content=content,
                campaign=request.campaign,
                department=request.department,
                audience=request.audience,
                sensitivity=request.sensitivity,
                beacons=beacons,
            )
            content_mode = content.generator_mode

        filename = safe_filename(content.title)
        artifact_dir = self.settings.generated_dir / artifact_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        final_path = (artifact_dir / filename).resolve()
        temporary = final_path.with_name(f".{final_path.name}.part")
        temporary.write_bytes(file_bytes)
        os.replace(temporary, final_path)
        created_at = utc_now()
        digest = sha256(file_bytes)

        campaign = {
            "id": campaign_id,
            "name": request.campaign,
            "objective": request.objective,
            "created_at": created_at,
        }
        artifact = {
            "id": artifact_id,
            "campaign_id": campaign_id,
            "title": content.title,
            "theme": request.theme,
            "department": request.department,
            "audience": request.audience,
            "sensitivity": request.sensitivity,
            "filename": filename,
            "file_path": str(final_path),
            "deployment_path": str(final_path),
            "document_format": "docx",
            "sensor_mode": request.sensor_mode.value,
            "local_token": local_token,
            "canary_url": canary_url,
            "canary_provider": canary_provider,
            "sha256": digest,
            "size_bytes": len(file_bytes),
            "content_mode": content_mode,
            "status": "ready",
            "created_at": created_at,
        }
        try:
            self.database.create_artifact(
                campaign=campaign,
                artifact=artifact,
                secrets=secrets_row,
            )
            self._record(
                artifact_id=artifact_id,
                source="janus",
                kind="artifact_generated",
                category=EvidenceCategory.OBSERVED,
                strength=EvidenceStrength.CONFIRMED,
                transport=TransportTrust.VERIFIED,
                summary=(
                    f"DOCX généré en mode {request.sensor_mode.value}; "
                    f"contenu déclaré {content_mode}."
                ),
                payload={
                    "artifact_id": artifact_id,
                    "filename": filename,
                    "sensor_mode": request.sensor_mode.value,
                    "sha256": digest,
                    "size_bytes": len(file_bytes),
                    "beacons": [
                        {"relationship_id": item.relationship_id, "url": item.url}
                        for item in beacons
                    ],
                },
                source_event_id=artifact_id,
                details={"content_mode": content_mode},
            )
        except Exception:
            final_path.unlink(missing_ok=True)
            if credentials:
                try:
                    self.canary_client.delete(credentials)
                except Exception:
                    pass
            raise

        public = self.database.get_artifact_public(artifact_id) or {}
        public.update(
            {
                "download_url": f"/api/artifacts/{artifact_id}/download",
                "pixel_test_url": (
                    f"/api/artifacts/{artifact_id}/pixel-test" if local_token else None
                ),
            }
        )
        return public

    @staticmethod
    def _validate_remote_canary_url(value: str | None) -> str:
        candidate = (value or "").strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise JanusError("Ajoutez une URL HTTP(S) Canarytoken complète pour ce mode.")
        return candidate

    def download_path(self, artifact_id: str) -> tuple[Path, dict[str, Any]]:
        artifact = self.database.get_artifact(artifact_id)
        if not artifact:
            raise JanusError("Artefact introuvable.")
        path = Path(artifact["file_path"]).resolve()
        generated_root = self.settings.generated_dir.resolve()
        if path != generated_root and generated_root not in path.parents:
            raise JanusError("Chemin d'artefact hors du stockage JANUS.")
        if not path.is_file():
            raise JanusError("Le fichier enregistré n'est plus disponible.")
        if hashlib.sha256(path.read_bytes()).hexdigest() != artifact["sha256"]:
            raise JanusError("L'empreinte du fichier ne correspond plus au registre.")
        return path, artifact

    def state(self) -> dict[str, Any]:
        return {
            "artifacts": self.database.list_artifacts(),
            "events": self.database.list_evidence(),
            "counters": self.database.counts(),
            "connectors": {
                "local_pixel": {
                    "status": "ready",
                    "proof": "Contact HTTP observé par cette instance; origine réseau non authentifiée.",
                },
                "ai": {
                    "status": "configured" if self.settings.ai_configured else "template",
                    "proof": (
                        f"Mode {self.settings.ai_mode}; l'origine exacte est inscrite par artefact."
                    ),
                },
                "canary": {
                    "status": (
                        "configured" if self.settings.canary_official_configured else "manual"
                    ),
                    "proof": (
                        "Adaptateur officiel disponible."
                        if self.settings.canary_official_configured
                        else "URL distante manuelle disponible; fournisseur officiel non configuré."
                    ),
                },
                "wazuh": {
                    "status": (
                        "configured"
                        if self.settings.wazuh_indexer_configured
                        else "waiting"
                    ),
                    "proof": (
                        "Indexer configuré; brut conservé avant normalisation."
                        if self.settings.wazuh_indexer_configured
                        else "Secret d'ingestion ou Indexer à configurer pour des événements réels."
                    ),
                    "collector": self.wazuh_poller_status,
                },
            },
            "generated_at": utc_now(),
        }

    def record_pixel(
        self,
        token: str,
        *,
        remote_ip: str | None,
        user_agent: str | None,
        headers: dict[str, str],
        query: dict[str, str],
        controlled: bool = False,
    ) -> bool:
        artifact = self.database.artifact_by_local_token(token)
        if not artifact:
            return False
        category = EvidenceCategory.CONTROLLED if controlled else EvidenceCategory.OBSERVED
        self._record(
            artifact_id=artifact["id"],
            source="janus_pixel",
            kind="pixel_contact",
            category=category,
            strength=EvidenceStrength.CONFIRMED,
            transport=TransportTrust.UNVERIFIED,
            summary=(
                "Test contrôlé du pixel JANUS."
                if controlled
                else "Contact HTTP reçu sur le pixel JANUS; l'ouverture humaine n'est pas déduite."
            ),
            payload={"headers": headers, "query": query, "remote_ip": remote_ip},
            source_event_id=None,
            dedupe_key=new_id("hit"),
            remote_ip=remote_ip,
            user_agent=user_agent,
            is_controlled=controlled,
        )
        return True

    def controlled_pixel_test(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.database.get_artifact(artifact_id)
        if not artifact:
            raise JanusError("Artefact introuvable pour le test du pixel.")
        token = artifact.get("local_token")
        if not token:
            raise JanusError("Cet artefact ne contient pas de pixel JANUS.")
        self.record_pixel(
            str(token),
            remote_ip="127.0.0.1",
            user_agent="JANUS-Controlled-Test/1.0",
            headers={"x-janus-test": "controlled"},
            query={"test": "1"},
            controlled=True,
        )
        return {"artifact_id": artifact_id, "recorded": True, "category": "controlled"}

    def ingest_canary(
        self,
        payload: dict[str, Any],
        *,
        transport: TransportTrust,
        raw_text: str | None = None,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        token_reference = str(
            payload.get("token")
            or payload.get("canarytoken")
            or payload.get("token_id")
            or ""
        )
        artifact = self.database.get_artifact(artifact_id) if artifact_id else None
        if not artifact and token_reference:
            artifact = self.database.artifact_by_canary_reference(token_reference)
        matched_id = artifact["id"] if artifact else None
        remote_ip = payload.get("src_ip") or payload.get("source_ip") or payload.get("ip")
        user_agent = payload.get("useragent") or payload.get("user_agent")
        source_event_id = str(
            payload.get("id")
            or payload.get("event_id")
            or payload.get("time_of_hit")
            or ""
        ) or None
        verified = transport == TransportTrust.VERIFIED
        raw_id, event_id, inserted = self._record(
            artifact_id=matched_id,
            source="canary",
            kind="canary_contact",
            category=EvidenceCategory.REPORTED,
            strength=(
                EvidenceStrength.CONFIRMED
                if verified and matched_id
                else EvidenceStrength.CANDIDATE
            ),
            transport=transport,
            summary=(
                "Contact Canary authentifié et associé à l'artefact."
                if verified and matched_id
                else "Événement Canary conservé; origine ou association non entièrement vérifiée."
            ),
            payload=payload,
            raw_text=raw_text,
            source_event_id=source_event_id,
            remote_ip=str(remote_ip) if remote_ip else None,
            user_agent=str(user_agent) if user_agent else None,
            observed_at=str(payload.get("time_of_hit") or payload.get("timestamp") or "") or None,
            details={"token_reference_present": bool(token_reference)},
        )
        return {"raw_event_id": raw_id, "event_id": event_id, "inserted": inserted, "artifact_id": matched_id}

    def refresh_canary_history(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.database.get_artifact(artifact_id)
        secret = self.database.get_artifact_secrets(artifact_id)
        if not artifact or not secret or not secret.get("provider_token"):
            raise JanusError("Cet artefact n'a pas de référence Canary officielle gérée.")
        credentials = TokenCredentials(
            token=str(secret["provider_token"]),
            auth_token=str(secret["provider_auth_token"]),
            token_url=str(artifact.get("canary_url") or ""),
            hostname=secret.get("provider_hostname"),
            token_type="ms_word",
        )
        payload = self.canary_client.history(credentials)
        inserted = 0
        for index, hit in enumerate(extract_history_hits(payload)):
            event_payload = {"provider_history_index": index, **hit, "token": credentials.token}
            result = self.ingest_canary(
                event_payload,
                transport=TransportTrust.VERIFIED,
                artifact_id=artifact_id,
            )
            inserted += int(result["inserted"])
        return {"artifact_id": artifact_id, "inserted": inserted, "hit_count": len(extract_history_hits(payload))}

    def ingest_wazuh(
        self,
        payload: dict[str, Any],
        transport: str | TransportTrust,
        *,
        raw_text: str | None = None,
        artifact_id: str | None = None,
        controlled: bool = False,
    ) -> dict[str, Any]:
        trust = transport if isinstance(transport, TransportTrust) else TransportTrust(transport)
        signal = parse_wazuh_signal(payload)
        artifact = self.database.get_artifact(artifact_id) if artifact_id else None
        if not artifact and signal.file_path:
            normalized = signal.file_path.replace("/", "\\").casefold()
            artifact = self.database.find_artifact_by_exact_path(normalized)
            if not artifact and signal.event_code == "5145":
                artifact = self.database.find_artifact_by_filename(
                    PureWindowsPath(signal.file_path).name
                )
        if (
            not artifact
            and signal.hostname
            and signal.logon_id
            and signal.observed_at
        ):
            artifact = self.database.artifact_for_session(
                hostname=signal.hostname,
                logon_id=signal.logon_id,
                observed_at=signal.observed_at,
            )

        matched_id = artifact["id"] if artifact else None
        if controlled:
            category = EvidenceCategory.CONTROLLED
        else:
            category = EvidenceCategory.OBSERVED
        if signal.kind == "normalization_pending":
            strength = EvidenceStrength.UNSUPPORTED
            summary = f"Événement Wazuh {signal.event_code or 'inconnu'} conservé; normalisation en attente."
        elif signal.event_code == "5145" and matched_id:
            strength = EvidenceStrength.CONFIRMED
            summary = "Accès SMB 5145 directement observé et associé au nom du honeydoc."
        elif matched_id:
            strength = EvidenceStrength.CANDIDATE
            summary = f"Signal Wazuh {signal.event_code} associé à l'artefact; corroboration recherchée."
        else:
            strength = EvidenceStrength.CANDIDATE
            summary = f"Signal Wazuh {signal.event_code or signal.kind} conservé sans artefact correspondant."

        raw_id, event_id, inserted = self._record(
            artifact_id=matched_id,
            source="wazuh",
            kind=signal.kind,
            category=category,
            strength=strength,
            transport=trust,
            summary=summary,
            payload=payload,
            raw_text=raw_text,
            source_event_id=signal.source_event_id,
            observed_at=signal.observed_at,
            remote_ip=signal.source_ip,
            hostname=signal.hostname,
            user_name=signal.user_name,
            process_name=signal.process_name,
            process_id=signal.process_id,
            process_guid=signal.process_guid,
            logon_id=signal.logon_id,
            file_path=signal.file_path,
            event_code=signal.event_code,
            action=signal.action,
            is_controlled=controlled,
            details={
                "command_line": signal.command_line,
                "parent_process_name": signal.parent_process_name,
                "source_port": signal.source_port,
            },
        )
        if inserted and matched_id and signal.hostname and signal.logon_id and signal.observed_at:
            self._correlate_session(matched_id, signal.hostname, signal.logon_id, signal.observed_at)
        return {
            "raw_event_id": raw_id,
            "event_id": event_id,
            "inserted": inserted,
            "artifact_id": matched_id,
            "normalized": signal.kind != "normalization_pending",
            "event_code": signal.event_code,
        }

    def controlled_wazuh_fixture(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.database.get_artifact(artifact_id)
        if not artifact:
            raise JanusError("Artefact introuvable pour le test contrôlé.")
        now = utc_now()
        payload = {
            "id": new_id("lab4663"),
            "timestamp": now,
            "agent": {"id": "lab", "name": "JANUS-LAB"},
            "data": {
                "win": {
                    "system": {
                        "eventID": "4663",
                        "computer": "JANUS-LAB",
                        "eventRecordID": str(secrets.randbelow(900000) + 100000),
                        "providerName": "Microsoft-Windows-Security-Auditing",
                    },
                    "eventdata": {
                        "subjectDomainName": "LAB",
                        "subjectUserName": "operateur",
                        "subjectLogonId": "0xJANUS",
                        "objectName": artifact["deployment_path"],
                        "processName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                        "processId": "0x1234",
                        "accessMask": "0x1",
                        "accessList": "%%4416",
                    },
                }
            },
            "janus_fixture": True,
        }
        return self.ingest_wazuh(
            payload,
            TransportTrust.VERIFIED,
            artifact_id=artifact_id,
            controlled=True,
        )

    def _correlate_session(self, artifact_id: str, hostname: str, logon_id: str, observed_at: str) -> None:
        events = self.database.session_events(
            artifact_id=artifact_id,
            hostname=hostname,
            logon_id=logon_id,
            observed_at=observed_at,
            seconds=5,
        )
        codes = {str(item.get("event_code") or "") for item in events}
        if "4663" in codes and ({"4688", "sysmon:1"} & codes):
            ids = [
                str(item["id"])
                for item in events
                if str(item.get("event_code") or "") in {"4663", "4688", "sysmon:1"}
            ]
            self.database.update_strength(
                ids,
                EvidenceStrength.CORROBORATED.value,
                " Corroboré par le même hôte et Logon ID dans une fenêtre de 5 s.",
            )

    def _record(
        self,
        *,
        artifact_id: str | None,
        source: str,
        kind: str,
        category: EvidenceCategory,
        strength: EvidenceStrength,
        transport: TransportTrust,
        summary: str,
        payload: Any,
        source_event_id: str | None,
        raw_text: str | None = None,
        dedupe_key: str | None = None,
        observed_at: str | None = None,
        remote_ip: str | None = None,
        user_agent: str | None = None,
        hostname: str | None = None,
        user_name: str | None = None,
        process_name: str | None = None,
        process_id: str | None = None,
        process_guid: str | None = None,
        logon_id: str | None = None,
        file_path: str | None = None,
        event_code: str | None = None,
        action: str | None = None,
        is_controlled: bool = False,
        details: dict[str, Any] | None = None,
    ) -> tuple[str, str, bool]:
        payload_json = raw_text if raw_text is not None else canonical_json(payload)
        payload_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        received_at = utc_now()
        raw_id = new_id("raw")
        evidence_id = new_id("evt")
        raw = {
            "id": raw_id,
            "artifact_id": artifact_id,
            "source": source,
            "source_event_id": source_event_id,
            "dedupe_key": dedupe_key or source_event_id or payload_sha,
            "received_at": received_at,
            "payload_sha256": payload_sha,
            "payload_json": payload_json,
            "transport_trust": transport.value,
        }
        evidence = {
            "id": evidence_id,
            "artifact_id": artifact_id,
            "source": source,
            "kind": kind,
            "category": category.value,
            "strength": strength.value,
            "transport_trust": transport.value,
            "summary": summary,
            "observed_at": observed_at,
            "received_at": received_at,
            "remote_ip": remote_ip,
            "user_agent": user_agent,
            "hostname": hostname,
            "user_name": user_name,
            "process_name": process_name,
            "process_id": process_id,
            "process_guid": process_guid,
            "logon_id": logon_id,
            "file_path": file_path,
            "event_code": event_code,
            "action": action,
            "is_controlled": is_controlled,
            "details": details or {},
        }
        return self.database.insert_raw_and_evidence(raw=raw, evidence=evidence)
