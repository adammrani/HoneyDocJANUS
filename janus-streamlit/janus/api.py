"""API FastAPI : plan de données stable derrière le dashboard Streamlit."""

from __future__ import annotations

import base64
import json
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response

from .ai import ContentGenerationError
from .canary import CanaryError
from .config import Settings
from .documents import DocumentError
from .models import GenerateRequest, TransportTrust
from .service import JanusError, JanusService
from .wazuh import WazuhIndexerPoller


PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def _client_is_local(request: Request) -> bool:
    host = request.client.host.casefold() if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _bearer_or_header(request: Request, header: str) -> str:
    supplied = request.headers.get(header, "")
    authorization = request.headers.get("authorization", "")
    if not supplied and authorization.casefold().startswith("bearer "):
        supplied = authorization[7:].strip()
    return supplied


def _request_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else None)


def create_app(settings: Settings | None = None, service: JanusService | None = None) -> FastAPI:
    selected_settings = settings or Settings.from_project()
    selected_service = service or JanusService(selected_settings)
    poller = WazuhIndexerPoller(
        selected_settings,
        lambda payload, trust: selected_service.ingest_wazuh(payload, trust),
    )
    selected_service.wazuh_poller_status = poller.status

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        poller.start()
        try:
            yield
        finally:
            poller.stop()

    api = FastAPI(
        title="JANUS Evidence Hub",
        version="0.2.0",
        description="Génération de honeydocs et conservation de preuves brutes.",
        lifespan=lifespan,
    )
    api.state.settings = selected_settings
    api.state.service = selected_service
    api.state.wazuh_poller = poller

    def require_admin(request: Request) -> None:
        expected = selected_settings.admin_api_key
        if not expected:
            if _client_is_local(request):
                return
            raise HTTPException(
                status_code=503,
                detail="JANUS_ADMIN_API_KEY doit être configurée pour une administration distante.",
            )
        supplied = _bearer_or_header(request, "x-janus-api-key")
        if not supplied or not secrets.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="Clé d'administration invalide.")

    @api.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ready",
            "database": selected_settings.database_path.exists(),
            "ai_mode": selected_settings.ai_mode,
            "ai_configured": selected_settings.ai_configured,
            "canary_official_configured": selected_settings.canary_official_configured,
            "wazuh_indexer_configured": selected_settings.wazuh_indexer_configured,
            "wazuh_ingest_protected": bool(selected_settings.wazuh_ingest_secret),
        }

    @api.get("/api/state", dependencies=[Depends(require_admin)])
    def state() -> dict[str, Any]:
        return selected_service.state()

    @api.post("/api/artifacts", status_code=201, dependencies=[Depends(require_admin)])
    def generate(payload: GenerateRequest) -> dict[str, Any]:
        try:
            return {"artifact": selected_service.generate(payload)}
        except (JanusError, ContentGenerationError, DocumentError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except CanaryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @api.get("/api/artifacts/{artifact_id}/download", dependencies=[Depends(require_admin)])
    def download(artifact_id: str) -> FileResponse:
        try:
            path, artifact = selected_service.download_path(artifact_id)
        except JanusError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(
            path,
            filename=artifact["filename"],
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"ETag": f'"{artifact["sha256"]}"'},
        )

    @api.get("/api/pixel/{token}")
    def pixel(token: str, request: Request) -> Response:
        query = dict(request.query_params)
        headers = {
            name: value
            for name, value in request.headers.items()
            if name.casefold() not in {"authorization", "cookie"}
        }
        selected_service.record_pixel(
            token,
            remote_ip=_request_ip(request),
            user_agent=request.headers.get("user-agent"),
            headers=headers,
            query=query,
        )
        return Response(
            PIXEL,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @api.post("/api/events/canary")
    async def canary_event(request: Request) -> dict[str, Any]:
        raw = (await request.body()).decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="JSON Canary invalide.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Objet JSON Canary attendu.")
        expected = selected_settings.canary_webhook_secret
        if expected:
            supplied = _bearer_or_header(request, "x-janus-webhook-secret")
            if not supplied or not secrets.compare_digest(supplied, expected):
                raise HTTPException(status_code=401, detail="Secret webhook Canary invalide.")
            trust = TransportTrust.VERIFIED
        else:
            trust = TransportTrust.UNVERIFIED
        return selected_service.ingest_canary(payload, transport=trust, raw_text=raw)

    @api.post("/api/events/wazuh")
    async def wazuh_event(request: Request) -> dict[str, Any]:
        expected = selected_settings.wazuh_ingest_secret
        if not expected:
            raise HTTPException(
                status_code=503,
                detail="WAZUH_INGEST_SECRET doit être configuré pour l'ingestion réelle.",
            )
        supplied = _bearer_or_header(request, "x-janus-wazuh-secret")
        if not supplied or not secrets.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="Secret d'ingestion Wazuh invalide.")
        raw = (await request.body()).decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="JSON Wazuh invalide.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Objet JSON Wazuh attendu.")
        return selected_service.ingest_wazuh(
            payload,
            TransportTrust.VERIFIED,
            raw_text=raw,
        )

    @api.post("/api/events/demo/{artifact_id}", dependencies=[Depends(require_admin)])
    def demo_event(artifact_id: str) -> dict[str, Any]:
        try:
            return selected_service.controlled_wazuh_fixture(artifact_id)
        except JanusError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post(
        "/api/artifacts/{artifact_id}/pixel-test",
        dependencies=[Depends(require_admin)],
    )
    def pixel_test(artifact_id: str) -> dict[str, Any]:
        try:
            return selected_service.controlled_pixel_test(artifact_id)
        except JanusError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post(
        "/api/artifacts/{artifact_id}/canary/refresh",
        dependencies=[Depends(require_admin)],
    )
    def refresh_canary(artifact_id: str) -> dict[str, Any]:
        try:
            return selected_service.refresh_canary_history(artifact_id)
        except JanusError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CanaryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @api.get("/api/raw/{raw_event_id}", dependencies=[Depends(require_admin)])
    def raw_event(raw_event_id: str) -> dict[str, Any]:
        value = selected_service.database.raw_event(raw_event_id)
        if not value:
            raise HTTPException(status_code=404, detail="Événement brut introuvable.")
        return value

    return api


app = create_app()
