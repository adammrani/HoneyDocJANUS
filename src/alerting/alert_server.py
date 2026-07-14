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

The SQLite database is created automatically on startup.
"""

import base64

from fastapi import FastAPI, Request
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
from src.detection.canarytoken_handler import create_token, parse_callback
from src.janus.document_assembler import assemble_document
from src.lifecycle.injector import deploy_document
from src.schemas.event_models import GenerateRequest, GenerateResponse
from src.tactical.coherence_check import check_coherence
from src.tactical.context_analyzer import build_prompt
from src.tactical.llm_engine import generate_content

_settings = get_settings()

app = FastAPI(title="Honey-Documents Dynamiques", version="1.0.0")

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


@app.on_event("startup")
def _startup() -> None:
    _settings.ensure_dirs()
    init_db()
    log.info("Alert server started. DB at %s", _settings.DB_PATH)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "honey-documents"}


@app.post("/generate_decoy", response_model=GenerateResponse)
def generate_decoy(req: GenerateRequest) -> GenerateResponse:
    """Run the full pipeline: token -> prompt -> LLM -> coherence -> assemble -> deploy."""
    log.info("generate_decoy: type=%s target=%s", req.doc_type, req.target_dir)

    # 1) Canarytoken
    token = create_token(memo=f"HoneyDoc {req.doc_type} -> {req.target_dir or 'local'}")

    # 2) Prompt from corpus + persona
    prompt = build_prompt(req.doc_type, req.target_dir)

    # 3) LLM content
    content = generate_content(prompt)

    # 4) Coherence gate (retry once if it fails)
    corpus_dir = _CORPUS_BY_TYPE.get(req.doc_type, "")
    if corpus_dir:
        result = check_coherence(content, corpus_dir)
        if not result["passed"]:
            log.info("Coherence failed (%.3f) — regenerating once", result["score"])
            content = generate_content(prompt)

    # 5/6) Assemble the .docx with the requested layers
    doc = assemble_document(
        content=content,
        doc_type=req.doc_type,
        token_id=token["token_id"],
        token_url=token["token_url"],
        enable_janus=req.enable_janus,
        enable_ci3=req.enable_ci3,
    )

    # 7) Deploy + persist
    deployment = deploy_document(
        doc=doc,
        doc_type=req.doc_type,
        token_id=token["token_id"],
        token_url=token["token_url"],
        callback_url=token["callback_url"],
        target_dir=req.target_dir,
        ttl_hours=req.ttl_hours,
    )

    return GenerateResponse(
        honeydoc_id=deployment["honeydoc_id"],
        filename=deployment["filename"],
        token_url=token["token_url"],
        deployed_path=deployment["deployed_path"],
        message="HoneyDoc généré et déployé avec succès.",
    )


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
        os_guess="Agent automatisé" if verdict["is_automated"] else "Inconnu",
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
