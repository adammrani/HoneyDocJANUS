"""
src/schemas/llm_models.py
Pydantic models describing the LLM prompt context and response.
"""

from typing import List

from pydantic import BaseModel, Field


class PromptContext(BaseModel):
    """Everything needed to build a generation prompt for one decoy."""

    doc_type: str
    persona: str
    corpus_dir: str
    corpus_samples: List[str] = Field(default_factory=list)
    target_dir: str = ""


class LLMResponse(BaseModel):
    """Wrapper around raw generated content plus provenance metadata."""

    content: str
    model: str
    fallback_used: bool = False
    char_count: int = 0
