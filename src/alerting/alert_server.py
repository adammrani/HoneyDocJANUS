"""
src/alerting/alert_server.py
FastAPI server: the standalone detection & response brain.

Endpoints:
  POST /generate_decoy   — run the full generation pipeline, deploy a honeydoc
  POST /alert            — receive a Canarytoken webhook, persist an alert
  GET  /ping/{token_id}  — local fallback beacon (returns a 1x1 PNG)
  GET  /ci1/{token_id}   — CI1 callback (an LLM agent followed the hidden line)
  GET  /alerts           — list recent alerts
  GET  /honeydocs        — list deployed honeydocs
  GET  /health           — liveness probe
  GET  /canary/status    — Canarytokens configuration (without secrets)
  POST /canary/test-token — create a harmless token for a manual email test
  GET  /generation/capabilities — implemented formats and detection layers

  GET  /wazuh/status     — automatic Wazuh collector health
  GET  /wazuh/detections — persisted Wazuh/JANUS verdicts
  GET  /telemetry/status — Windows/Linux forensic collector health
  GET  /telemetry/signals — normalized forensic observations

The SQLite database is created automatically on startup.
"""

import base64
import json
import secrets
import sys
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from src.core.config import get_settings
from src.core.database import (
    get_token_by_id,
    init_db,
    insert_alert,
    list_alerts,
    list_honeydocs,
)
from src.core.logger import log
from src.detection.callback_listener import process_ci1_callback
from src.detection.canarytoken_handler import (
    CanarytokenProviderError,
    create_remote_token,
    create_token,
    get_canary_status,
    parse_callback,
)
from src.janus.document_assembler import assemble_document
from src.janus.generators.accounting_workbook import (
    GENERATOR_VERSION as ACCOUNTING_GENERATOR_VERSION,
    build_accounting_workbook,
)
from src.janus.generators.structured_decoy import (
    GENERATOR_VERSION as STRUCTURED_GENERATOR_VERSION,
    SUPPORTED_FORMATS_BY_TYPE,
    build_structured_decoy,
    is_supported_combination,
)
from src.janus_v2.deployment.path_policy import (
    DeploymentPathError,
    resolve_deployment_target,
)
from src.janus_v2.correlation.attack_timeline import build_attack_timeline
from src.janus_v2.detection.wazuh_collector import (
    WazuhCollector,
    WazuhCollectorConfig,
)
from src.janus_v2.detection.forensic_collector import (
    ForensicCollector,
    ForensicCollectorConfig,
)
from src.janus_v2.registry.security_signal_store import (
    SqliteSecuritySignalStore,
)
from src.janus_v2.registry.sqlite_registry import SqliteDecoyRegistry
from src.janus_v2.registry.wazuh_detection_store import (
    SqliteWazuhDetectionStore,
)
from src.janus_v2.telemetry.wazuh_indexer_client import WazuhIndexerClient
from src.lifecycle.injector import deploy_document
from src.schemas.event_models import GenerateRequest, GenerateResponse
from src.tactical.coherence_check import check_coherence
from src.tactical.context_analyzer import build_prompt
from src.tactical.llm_engine import generate_content

_settings = get_settings()

_wazuh_store = SqliteWazuhDetectionStore(_settings.DB_PATH)
_wazuh_collector: WazuhCollector | None = None
_wazuh_thread: threading.Thread | None = None
_wazuh_stop_event = threading.Event()
_wazuh_start_error: str | None = None

_forensic_store = SqliteSecuritySignalStore(_settings.DB_PATH)
_forensic_collector: ForensicCollector | None = None
_forensic_thread: threading.Thread | None = None
_forensic_stop_event = threading.Event()
_forensic_start_error: str | None = None

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _settings.ensure_dirs()
    init_db()
    _start_wazuh_collector()
    _start_forensic_collector()
    if not _settings.JANUS_ADMIN_API_KEY:
        log.warning(
            "JANUS_ADMIN_API_KEY is empty: administrative routes are local-only."
        )
    log.info("Alert server started. DB at %s", _settings.DB_PATH)
    try:
        yield
    finally:
        _wazuh_stop_event.set()
        _forensic_stop_event.set()
        if _wazuh_thread is not None and _wazuh_thread.is_alive():
            _wazuh_thread.join(timeout=5)
        if _forensic_thread is not None and _forensic_thread.is_alive():
            _forensic_thread.join(timeout=5)


app = FastAPI(
    title="Honey-Documents Dynamiques",
    version="2.0.0",
    lifespan=_lifespan,
)

# 1x1 transparent PNG (returned by the fallback beacon).
_PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# Map decoy type -> corpus dir for the coherence gate.
_CORPUS_BY_TYPE = {
    "financial_report": "corpus/financial",
    "hr_document": "corpus/hr",
    "technical_config": "corpus/technical",
    "cloud_credentials": "corpus/technical",
}


def _is_local_request(request: Request) -> bool:
    host = request.client.host.casefold() if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def require_admin(request: Request) -> None:
    """Protect administrative routes while keeping local development usable."""

    expected = _settings.JANUS_ADMIN_API_KEY
    if not expected:
        if _settings.JANUS_ALLOW_UNAUTHENTICATED_LOCAL and _is_local_request(request):
            return
        raise HTTPException(
            status_code=503,
            detail="JANUS_ADMIN_API_KEY doit être configurée pour un accès distant.",
        )

    supplied = request.headers.get("x-janus-api-key", "")
    authorization = request.headers.get("authorization", "")
    if not supplied and authorization.casefold().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=401,
            detail="Clé d'administration JANUS invalide ou absente.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _detection_layers(req: GenerateRequest) -> list[str]:
    """Return only detection mechanisms that the generated format can use."""

    layers = ["wazuh_sacl"]
    if req.output_format in {"docx", "xlsx"}:
        layers.append("document_beacon")
    else:
        layers.append("url_breadcrumb")
    if req.enable_ci3 and req.output_format == "docx":
        layers.append("credential_honeypot")
    if req.output_format in {"env", "yaml", "json", "zip"} and req.doc_type in {
        "technical_config",
        "cloud_credentials",
    }:
        layers.append("credential_honeypot")
    return layers


def _start_wazuh_collector() -> None:
    global _wazuh_collector, _wazuh_thread, _wazuh_start_error

    _wazuh_store.initialize()
    if not _settings.WAZUH_AUTO_COLLECT_ENABLED:
        log.info("Automatic Wazuh collection is disabled.")
        return
    if not _settings.wazuh_indexer_configured:
        _wazuh_start_error = (
            "Collecte Wazuh activée, mais les identifiants Indexer sont absents."
        )
        log.warning(_wazuh_start_error)
        return
    if _wazuh_thread is not None and _wazuh_thread.is_alive():
        return

    try:
        source = WazuhIndexerClient(
            base_url=_settings.WAZUH_INDEXER_URL,
            username=_settings.WAZUH_INDEXER_USERNAME,
            password=_settings.WAZUH_INDEXER_PASSWORD,
            index_pattern=_settings.WAZUH_INDEX_PATTERN,
            verify_ssl=_settings.WAZUH_VERIFY_SSL,
            ca_cert_path=_settings.WAZUH_CA_CERT_PATH or None,
            timeout_seconds=_settings.WAZUH_REQUEST_TIMEOUT_SECONDS,
        )
        registry = SqliteDecoyRegistry(_settings.DB_PATH)
        _wazuh_collector = WazuhCollector(
            source=source,
            registry=registry,
            store=_wazuh_store,
            config=WazuhCollectorConfig(
                rule_id=_settings.WAZUH_RULE_ID,
                additional_rule_ids=_settings.WAZUH_ADDITIONAL_RULE_IDS,
                batch_size=_settings.WAZUH_BATCH_SIZE,
                initial_lookback_minutes=(
                    _settings.WAZUH_INITIAL_LOOKBACK_MINUTES
                ),
                overlap_seconds=_settings.WAZUH_OVERLAP_SECONDS,
                settle_seconds=_settings.WAZUH_EVENT_SETTLE_SECONDS,
                poll_interval_seconds=(
                    _settings.WAZUH_POLL_INTERVAL_SECONDS
                ),
                deployment_grace_seconds=(
                    _settings.WAZUH_DEPLOYMENT_GRACE_SECONDS
                ),
                trusted_process_path=sys.executable,
            ),
            logger=log,
        )
    except Exception as error:  # noqa: BLE001 - API must remain available
        _wazuh_start_error = str(error)
        log.warning("Could not configure Wazuh collector: %s", error)
        return

    _wazuh_start_error = None
    _wazuh_stop_event.clear()
    _wazuh_thread = threading.Thread(
        target=_wazuh_collector.run_forever,
        args=(_wazuh_stop_event,),
        name="janus-wazuh-collector",
        daemon=True,
    )
    _wazuh_thread.start()
    log.info("Automatic Wazuh collection started (rule %s).", _settings.WAZUH_RULE_ID)


def _wazuh_status() -> dict:
    status = {
        "enabled": _settings.WAZUH_AUTO_COLLECT_ENABLED,
        "configured": _settings.wazuh_indexer_configured,
        "rule_id": _settings.WAZUH_RULE_ID,
        "indexer_url": _settings.WAZUH_INDEXER_URL,
        "running": False,
        "last_error": _wazuh_start_error,
        "processed_total": _wazuh_store.count(),
    }
    if _wazuh_collector is not None:
        status.update(_wazuh_collector.status())
    return status


def _start_forensic_collector() -> None:
    global _forensic_collector, _forensic_thread, _forensic_start_error

    _forensic_store.initialize()
    if not _settings.FORENSIC_TELEMETRY_ENABLED:
        log.info("Forensic telemetry collection is disabled.")
        return
    if not _settings.forensic_telemetry_configured:
        _forensic_start_error = (
            "Télémétrie activée, mais les identifiants Indexer sont absents."
        )
        log.warning(_forensic_start_error)
        return
    if _forensic_thread is not None and _forensic_thread.is_alive():
        return

    try:
        source = WazuhIndexerClient(
            base_url=_settings.WAZUH_INDEXER_URL,
            username=_settings.WAZUH_INDEXER_USERNAME,
            password=_settings.WAZUH_INDEXER_PASSWORD,
            index_pattern=_settings.WAZUH_INDEX_PATTERN,
            verify_ssl=_settings.WAZUH_VERIFY_SSL,
            ca_cert_path=_settings.WAZUH_CA_CERT_PATH or None,
            timeout_seconds=_settings.WAZUH_REQUEST_TIMEOUT_SECONDS,
        )
        _forensic_collector = ForensicCollector(
            source=source,
            store=_forensic_store,
            config=ForensicCollectorConfig(
                windows_event_ids=_settings.FORENSIC_WINDOWS_EVENT_IDS,
                audit_keys=_settings.FORENSIC_AUDIT_KEYS,
                agent_ids=_settings.FORENSIC_AGENT_IDS,
                accepted_logon_types=_settings.FORENSIC_LOGON_TYPES,
                batch_size=_settings.WAZUH_BATCH_SIZE,
                initial_lookback_minutes=_settings.WAZUH_INITIAL_LOOKBACK_MINUTES,
                overlap_seconds=_settings.WAZUH_OVERLAP_SECONDS,
                settle_seconds=_settings.WAZUH_EVENT_SETTLE_SECONDS,
                poll_interval_seconds=_settings.WAZUH_POLL_INTERVAL_SECONDS,
            ),
            logger=log,
        )
    except Exception as error:  # noqa: BLE001 - l'API doit rester disponible
        _forensic_start_error = str(error)
        log.warning("Could not configure forensic collector: %s", error)
        return

    _forensic_start_error = None
    _forensic_stop_event.clear()
    _forensic_thread = threading.Thread(
        target=_forensic_collector.run_forever,
        args=(_forensic_stop_event,),
        name="janus-forensic-collector",
        daemon=True,
    )
    _forensic_thread.start()
    log.info("Windows/Linux forensic telemetry collection started.")


def _forensic_status() -> dict:
    status = {
        "enabled": _settings.FORENSIC_TELEMETRY_ENABLED,
        "configured": _settings.forensic_telemetry_configured,
        "windows_event_ids": list(_settings.FORENSIC_WINDOWS_EVENT_IDS),
        "audit_keys": list(_settings.FORENSIC_AUDIT_KEYS),
        "agent_ids": list(_settings.FORENSIC_AGENT_IDS),
        "accepted_logon_types": list(_settings.FORENSIC_LOGON_TYPES),
        "running": False,
        "last_error": _forensic_start_error,
        "processed_total": _forensic_store.count(),
    }
    if _forensic_collector is not None:
        status.update(_forensic_collector.status())
    return status


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "honey-documents",
        "version": app.version,
        "admin_auth_configured": bool(_settings.JANUS_ADMIN_API_KEY),
    }


@app.get("/canary/status", dependencies=[Depends(require_admin)])
def canary_status() -> dict:
    """Expose provider readiness without returning the configured email."""
    return get_canary_status()


@app.post("/canary/test-token", dependencies=[Depends(require_admin)])
def create_canary_test_token(request: Request) -> dict:
    """Create, but never trigger, a web token for a controlled email test."""
    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        raise HTTPException(
            status_code=403,
            detail="Ce test Canarytoken est réservé à un appel local.",
        )
    try:
        token = create_remote_token(
            memo="JANUS - validation manuelle de la notification",
            token_type="web",
        )
    except CanarytokenProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "status": "created_not_triggered",
        "provider": token["provider"],
        "token_type": token["token_type"],
        "token_url": token["token_url"],
        "activation": token["activation_mode"],
        "instruction": (
            "Ouvrez token_url une seule fois pour déclencher l'e-mail de test."
        ),
    }


@app.post(
    "/generate_decoy",
    response_model=GenerateResponse,
    dependencies=[Depends(require_admin)],
)
def generate_decoy(req: GenerateRequest) -> GenerateResponse:
    """Run the full pipeline: token -> prompt -> LLM -> coherence -> assemble -> deploy."""
    try:
        deployment_target = resolve_deployment_target(
            requested_path=req.target_dir,
            allowed_root=_settings.JANUS_DEPLOY_ROOT,
        )
    except DeploymentPathError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    log.info(
        "generate_decoy: type=%s format=%s target=%s",
        req.doc_type,
        req.output_format,
        deployment_target,
    )

    if not is_supported_combination(req.doc_type, req.output_format):
        allowed = ", ".join(SUPPORTED_FORMATS_BY_TYPE.get(req.doc_type, ()))
        raise HTTPException(
            status_code=400,
            detail=(
                f"Format {req.output_format} indisponible pour {req.doc_type}. "
                f"Formats permis : {allowed}."
            ),
        )

    scenario = req.scenario.strip() or (
        "financial_accounting" if req.output_format == "xlsx" else req.doc_type
    )

    token_type = "msexcel" if req.output_format == "xlsx" else "web"
    token = create_token(
        memo=f"HoneyDoc {req.doc_type}/{req.output_format} -> {deployment_target}",
        allow_remote=True,
        token_type=token_type,
    )

    # 2) Prompt from corpus + persona
    prompt = build_prompt(req.doc_type, deployment_target)

    # 3) LLM content
    content = generate_content(prompt)

    # 4) Coherence gate (retry once if it fails)
    corpus_dir = _CORPUS_BY_TYPE.get(req.doc_type, "")
    if corpus_dir:
        result = check_coherence(content, corpus_dir)
        if not result["passed"]:
            log.info("Coherence failed (%.3f) — regenerating once", result["score"])
            content = generate_content(prompt)

    # 5/6) Assemble l'artefact demandé.
    if req.output_format == "xlsx":
        doc = build_accounting_workbook(
            summary_text=content,
            token_id=token["token_id"],
            token_url=token["token_url"],
            company_name=req.company_name or "Atlas Conseil & Industrie SA",
            fiscal_year=req.fiscal_year,
        )
        generator_version = ACCOUNTING_GENERATOR_VERSION
    elif req.output_format == "docx":
        doc = assemble_document(
            content=content,
            doc_type=req.doc_type,
            token_id=token["token_id"],
            token_url=token["token_url"],
            enable_janus=req.enable_janus,
            enable_ci3=req.enable_ci3,
        )
        generator_version = "janus-docx/1.0"
    else:
        doc = build_structured_decoy(
            doc_type=req.doc_type,
            output_format=req.output_format,
            summary_text=content,
            token_id=token["token_id"],
            token_url=token["token_url"],
            company_name=req.company_name or "Atlas Conseil & Industrie SA",
            fiscal_year=req.fiscal_year,
        )
        generator_version = STRUCTURED_GENERATOR_VERSION

    # 7) Deploy + persist
    deployment = deploy_document(
        doc=doc,
        doc_type=req.doc_type,
        token_id=token["token_id"],
        token_url=token["token_url"],
        callback_url=token["callback_url"],
        token_provider=token["provider"],
        token_type=token["token_type"],
        token_auth_token=token["auth_token"],
        token_activation=token["activation_mode"],
        target_dir=deployment_target,
        ttl_hours=req.ttl_hours,
        strict_target=True,
        output_format=req.output_format,
        scenario=scenario,
        generator_version=generator_version,
    )

    return GenerateResponse(
        honeydoc_id=deployment["honeydoc_id"],
        filename=deployment["filename"],
        token_url=token["token_url"],
        deployed_path=deployment["deployed_path"],
        message="HoneyDoc généré et déployé avec succès.",
        file_format=deployment["file_format"],
        scenario=deployment["scenario"],
        sha256=deployment["sha256"],
        token_activation=token["activation_mode"],
        token_provider=token["provider"],
        token_type=token["token_type"],
        canary_webhook_enabled=_settings.CANARYTOKEN_WEBHOOK_ENABLED,
        detection_layers=_detection_layers(req),
    )


@app.get("/generation/capabilities")
def generation_capabilities() -> dict:
    """Expose les formats réellement implémentés sans survendre la détection."""

    return {
        "formats": [
            {
                "id": output_format,
                "doc_types": [
                    doc_type
                    for doc_type, formats in SUPPORTED_FORMATS_BY_TYPE.items()
                    if output_format in formats
                ],
                "automatic_callback_on_open": output_format in {"docx", "xlsx"},
                "token_type": "msexcel" if output_format == "xlsx" else "web",
            }
            for output_format in ("docx", "xlsx", "csv", "json", "yaml", "env", "zip")
        ],
        "local_detection": "wazuh_sacl",
        "macros_required": False,
    }


@app.post("/alert")
async def receive_alert(request: Request) -> dict:
    """Receive a known Canarytoken webhook and persist a bounded payload."""

    body = await request.body()
    if len(body) > 64 * 1024:
        raise HTTPException(status_code=413, detail="Callback trop volumineux.")
    try:
        payload = json.loads(body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=400, detail="Callback JSON invalide.") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Le callback doit être un objet JSON.")

    enriched = parse_callback(payload)
    token_row = get_token_by_id(enriched.get("token_id") or "")
    if token_row is None:
        raise HTTPException(status_code=404, detail="Token JANUS inconnu.")
    honeydoc_id = token_row["honeydoc_id"]

    alert_id = insert_alert(
        token_id=enriched.get("token_id"),
        honeydoc_id=honeydoc_id,
        src_ip=enriched.get("src_ip"),
        user_agent=enriched.get("user_agent"),
        geo_country=enriched.get("geo_country"),
        geo_city=enriched.get("geo_city"),
        os_guess=enriched.get("os_guess"),
        os_evidence_source=enriched.get("os_evidence_source", "none"),
        os_confidence=enriched.get("os_confidence", "none"),
        os_scope=enriched.get("os_scope", "unknown"),
        browser_guess=enriched.get("browser_guess"),
        raw_payload=enriched.get("raw_payload"),
    )
    log.warning("ALERT #%s recorded (ip=%s)", alert_id, enriched.get("src_ip"))
    return {"status": "recorded", "alert_id": alert_id}


@app.get("/ping/{token_id}")
def ping_beacon(token_id: str, request: Request) -> Response:
    """Local fallback beacon: record the hit and return a 1x1 transparent PNG."""
    token_row = get_token_by_id(token_id)
    if token_row is None:
        raise HTTPException(status_code=404, detail="Token JANUS inconnu.")

    src_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    enriched = parse_callback({"token_id": token_id, "src_ip": src_ip, "user_agent": user_agent})

    honeydoc_id = token_row["honeydoc_id"]

    insert_alert(
        token_id=token_id,
        honeydoc_id=honeydoc_id,
        src_ip=src_ip,
        user_agent=user_agent,
        geo_country=enriched.get("geo_country"),
        geo_city=enriched.get("geo_city"),
        os_guess=enriched.get("os_guess"),
        os_evidence_source=enriched.get("os_evidence_source", "none"),
        os_confidence=enriched.get("os_confidence", "none"),
        os_scope=enriched.get("os_scope", "unknown"),
        browser_guess=enriched.get("browser_guess"),
        raw_payload=enriched.get("raw_payload"),
    )
    log.warning("PING beacon hit (token=%s ip=%s)", token_id, src_ip)
    return Response(
        content=_PIXEL_PNG,
        media_type="image/png",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@app.get("/ci1/{token_id}")
def ci1_callback(token_id: str, request: Request) -> dict:
    """CI1 callback: an automated LLM agent followed the hidden instruction."""
    token_row = get_token_by_id(token_id)
    if token_row is None:
        raise HTTPException(status_code=404, detail="Token JANUS inconnu.")

    src_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    verdict = process_ci1_callback(token_id, src_ip, user_agent)

    honeydoc_id = token_row["honeydoc_id"]

    insert_alert(
        token_id=f"CI1_{token_id}",
        honeydoc_id=honeydoc_id,
        src_ip=src_ip,
        user_agent=user_agent,
        os_guess=None,
        os_evidence_source="none",
        os_confidence="none",
        os_scope="unknown",
        browser_guess=f"CI1 LLM agent (conf={verdict['confidence']})",
        raw_payload=verdict,
    )
    return {"status": "verified", **verdict}


@app.get("/alerts", dependencies=[Depends(require_admin)])
def get_alerts(limit: int = Query(default=100, ge=1, le=500)) -> JSONResponse:
    return JSONResponse(content=list_alerts(limit=limit))


@app.get("/honeydocs", dependencies=[Depends(require_admin)])
def get_honeydocs() -> JSONResponse:
    return JSONResponse(content=list_honeydocs())


@app.get("/wazuh/status", dependencies=[Depends(require_admin)])
def get_wazuh_status() -> JSONResponse:
    """Return collector health without exposing Indexer credentials."""

    return JSONResponse(content=_wazuh_status())


@app.get("/wazuh/detections", dependencies=[Depends(require_admin)])
def get_wazuh_detections(
    limit: int = Query(default=100, ge=1, le=500),
    matched_only: bool = False,
) -> JSONResponse:
    """List persisted Wazuh events and their JANUS verdicts."""

    return JSONResponse(
        content=_wazuh_store.list_detections(
            limit=limit,
            matched_only=matched_only,
        )
    )


@app.get("/telemetry/status", dependencies=[Depends(require_admin)])
def get_telemetry_status() -> JSONResponse:
    """Expose l'état du collecteur sans révéler les identifiants Wazuh."""

    return JSONResponse(content=_forensic_status())


@app.get("/telemetry/signals", dependencies=[Depends(require_admin)])
def get_telemetry_signals(
    limit: int = Query(default=100, ge=1, le=500),
    kind: str | None = Query(default=None, max_length=64),
    platform: str | None = Query(default=None, max_length=32),
) -> JSONResponse:
    """Liste les preuves normalisées; filtres facultatifs par type et OS."""

    return JSONResponse(
        content=_forensic_store.list_signals(
            limit=limit,
            kind=kind,
            platform=platform,
        )
    )


@app.get("/telemetry/timeline", dependencies=[Depends(require_admin)])
def get_telemetry_timeline(
    logon_id: str = Query(min_length=1, max_length=128),
    hostname: str = Query(min_length=1, max_length=255),
    limit: int = Query(default=500, ge=1, le=2000),
) -> JSONResponse:
    """Reconstruit une session à partir d'un Logon ID Windows explicite."""

    signals = _forensic_store.list_timeline(
        logon_id=logon_id,
        hostname=hostname,
        limit=limit,
    )
    return JSONResponse(content=build_attack_timeline(signals))
