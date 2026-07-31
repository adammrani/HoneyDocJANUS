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
import sys
import threading

from fastapi import FastAPI, HTTPException, Request
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

app = FastAPI(title="Honey-Documents Dynamiques", version="1.4.0")

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
}


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


@app.on_event("startup")
def _startup() -> None:
    _settings.ensure_dirs()
    init_db()
    _start_wazuh_collector()
    _start_forensic_collector()
    log.info("Alert server started. DB at %s", _settings.DB_PATH)


@app.on_event("shutdown")
def _shutdown() -> None:
    _wazuh_stop_event.set()
    _forensic_stop_event.set()
    if _wazuh_thread is not None and _wazuh_thread.is_alive():
        _wazuh_thread.join(timeout=5)
    if _forensic_thread is not None and _forensic_thread.is_alive():
        _forensic_thread.join(timeout=5)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "honey-documents"}


@app.get("/canary/status")
def canary_status() -> dict:
    """Expose provider readiness without returning the configured email."""
    return get_canary_status()


@app.post("/canary/test-token")
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


@app.post("/generate_decoy", response_model=GenerateResponse)
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

    if req.output_format == "xlsx" and req.doc_type != "financial_report":
        raise HTTPException(
            status_code=400,
            detail="Le format xlsx est actuellement disponible pour financial_report.",
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
    else:
        doc = assemble_document(
            content=content,
            doc_type=req.doc_type,
            token_id=token["token_id"],
            token_url=token["token_url"],
            enable_janus=req.enable_janus,
            enable_ci3=req.enable_ci3,
        )
        generator_version = "janus-docx/1.0"

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
        detection_layers=["wazuh_sacl", "document_beacon"],
    )


@app.get("/generation/capabilities")
def generation_capabilities() -> dict:
    """Expose les formats réellement implémentés sans survendre la détection."""

    return {
        "formats": [
            {
                "id": "docx",
                "doc_types": [
                    "financial_report",
                    "hr_document",
                    "technical_config",
                ],
                "scenarios": ["narrative"],
                "canary_activation": "automatic_when_configured",
            },
            {
                "id": "xlsx",
                "doc_types": ["financial_report"],
                "scenarios": ["financial_accounting"],
                "canary_activation": "automatic_when_configured",
                "token_type": "msexcel",
            },
        ],
        "local_detection": "wazuh_sacl",
        "macros_required": False,
    }


@app.post("/alert")
async def receive_alert(request: Request) -> dict:
    """Receive a Canarytoken (or decoy-infra) webhook and persist an alert."""
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001 — accept any body shape
        payload = {}

    enriched = parse_callback(payload)
    token_row = get_token_by_id(enriched.get("token_id") or "")
    honeydoc_id = token_row["honeydoc_id"] if token_row else None

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
    src_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    enriched = parse_callback({"token_id": token_id, "src_ip": src_ip, "user_agent": user_agent})

    token_row = get_token_by_id(token_id)
    honeydoc_id = token_row["honeydoc_id"] if token_row else None

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
    return Response(content=_PIXEL_PNG, media_type="image/png")


@app.get("/ci1/{token_id}")
def ci1_callback(token_id: str, request: Request) -> dict:
    """CI1 callback: an automated LLM agent followed the hidden instruction."""
    src_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    verdict = process_ci1_callback(token_id, src_ip, user_agent)

    token_row = get_token_by_id(token_id)
    honeydoc_id = token_row["honeydoc_id"] if token_row else None

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


@app.get("/alerts")
def get_alerts(limit: int = 100) -> JSONResponse:
    return JSONResponse(content=list_alerts(limit=limit))


@app.get("/honeydocs")
def get_honeydocs() -> JSONResponse:
    return JSONResponse(content=list_honeydocs())


@app.get("/wazuh/status")
def get_wazuh_status() -> JSONResponse:
    """Return collector health without exposing Indexer credentials."""

    return JSONResponse(content=_wazuh_status())


@app.get("/wazuh/detections")
def get_wazuh_detections(
    limit: int = 100,
    matched_only: bool = False,
) -> JSONResponse:
    """List persisted Wazuh events and their JANUS verdicts."""

    return JSONResponse(
        content=_wazuh_store.list_detections(
            limit=limit,
            matched_only=matched_only,
        )
    )


@app.get("/telemetry/status")
def get_telemetry_status() -> JSONResponse:
    """Expose l'état du collecteur sans révéler les identifiants Wazuh."""

    return JSONResponse(content=_forensic_status())


@app.get("/telemetry/signals")
def get_telemetry_signals(
    limit: int = 100,
    kind: str | None = None,
    platform: str | None = None,
) -> JSONResponse:
    """Liste les preuves normalisées; filtres facultatifs par type et OS."""

    return JSONResponse(
        content=_forensic_store.list_signals(
            limit=limit,
            kind=kind,
            platform=platform,
        )
    )


@app.get("/telemetry/timeline")
def get_telemetry_timeline(
    logon_id: str,
    hostname: str,
    limit: int = 500,
) -> JSONResponse:
    """Reconstruit une session à partir d'un Logon ID Windows explicite."""

    signals = _forensic_store.list_timeline(
        logon_id=logon_id,
        hostname=hostname,
        limit=limit,
    )
    return JSONResponse(content=build_attack_timeline(signals))
