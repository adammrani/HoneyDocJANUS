"""
src/schemas/event_models.py
Pydantic models for the FastAPI request/response payloads.
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class GenerateRequest(BaseModel):
    """Body of POST /generate_decoy."""

    doc_type: Literal[
        "financial_report",
        "hr_document",
        "technical_config",
        "cloud_credentials",
    ] = Field(..., description="Catégorie métier du leurre")
    target_dir: str = Field(default="", max_length=1024)
    ttl_hours: int = Field(default=72, ge=1, le=8760)
    enable_janus: bool = True
    enable_ci3: bool = True
    output_format: Literal[
        "docx",
        "xlsx",
        "csv",
        "json",
        "yaml",
        "env",
        "zip",
    ] = "docx"
    scenario: str = Field(default="", max_length=120)
    company_name: Optional[str] = Field(default=None, max_length=120)
    fiscal_year: int = Field(
        default_factory=lambda: datetime.now().year,
        ge=2020,
        le=2100,
    )


class GenerateResponse(BaseModel):
    """Response of POST /generate_decoy."""

    honeydoc_id: int
    filename: str
    token_url: str
    deployed_path: str
    message: str
    file_format: str = "docx"
    scenario: str = ""
    sha256: str = ""
    token_activation: str = "automatic"
    token_provider: str = "local"
    token_type: str = "web"
    canary_webhook_enabled: bool = False
    detection_layers: list[str] = Field(default_factory=list)


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
    os_evidence_source: str = "none"
    os_confidence: str = "none"
    os_scope: str = "unknown"
    browser_guess: Optional[str] = None
