"""
src/schemas/event_models.py
Pydantic models for the FastAPI request/response payloads.
"""

from typing import Optional

from pydantic import BaseModel, Field


class GenerateRequest(BaseModel):
    """Body of POST /generate_decoy."""

    doc_type: str = Field(..., description="financial_report | hr_document | technical_config")
    target_dir: str = ""
    ttl_hours: int = 72
    enable_janus: bool = True
    enable_ci3: bool = True


class GenerateResponse(BaseModel):
    """Response of POST /generate_decoy."""

    honeydoc_id: int
    filename: str
    token_url: str
    deployed_path: str
    message: str


class CanarytokenCallback(BaseModel):
    """Loose model of an incoming Canarytoken webhook payload."""

    token_id: Optional[str] = None
    src_ip: Optional[str] = None
    user_agent: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None


class AlertSummary(BaseModel):
    """Normalised alert as returned by GET /alerts."""

    id: int
    token_id: Optional[str] = None
    honeydoc_id: Optional[int] = None
    honeydoc_filename: Optional[str] = None
    triggered_at: str
    src_ip: Optional[str] = None
    user_agent: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    os_guess: Optional[str] = None
    browser_guess: Optional[str] = None
