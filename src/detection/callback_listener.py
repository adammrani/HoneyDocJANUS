"""
src/detection/callback_listener.py
CI1-specific callback processing.

The CI1 layer plants a hidden instruction inside the decoy document aimed at
automated LLM triage agents. If such an agent fetches our /ci1/{token_id}
endpoint, it has revealed itself. This module scores how confident we are that
the caller was automated, based on the User-Agent.
"""

from src.core.logger import log

# Weighted signals that the caller is an automated agent rather than a human
# opening the document in a normal browser.
_CONFIDENCE_SIGNALS = {
    "langchain": 0.95,
    "llamaindex": 0.95,
    "openai": 0.9,
    "anthropic": 0.9,
    "python-requests": 0.85,
    "httpx": 0.85,
    "aiohttp": 0.85,
    "python-urllib": 0.8,
    "node-fetch": 0.8,
    "axios": 0.75,
    "curl": 0.7,
    "wget": 0.7,
    "go-http": 0.7,
    "okhttp": 0.6,
}


def process_ci1_callback(token_id: str, src_ip: str, user_agent: str) -> dict:
    """
    Analyse a CI1 callback and return a structured verdict.

    Returns:
        {
          "trigger": "CI1_LLM_AGENT",
          "confidence": float,   # 0..1 that the access was automated
          "is_automated": bool,
          "token_id": str,
          "src_ip": str,
          "user_agent": str,
        }
    """
    ua_lower = (user_agent or "").lower()

    confidence = 0.0
    for needle, weight in _CONFIDENCE_SIGNALS.items():
        if needle in ua_lower:
            confidence = max(confidence, weight)

    # An empty User-Agent on a /ci1 hit is itself suspicious: no real browser
    # follows a hidden instruction and omits its UA.
    if not ua_lower:
        confidence = max(confidence, 0.5)

    is_automated = confidence >= 0.5

    log.warning(
        "CI1 callback (token=%s ip=%s automated=%s conf=%.2f) UA=%r",
        token_id,
        src_ip,
        is_automated,
        confidence,
        user_agent,
    )

    return {
        "trigger": "CI1_LLM_AGENT",
        "confidence": round(confidence, 2),
        "is_automated": is_automated,
        "token_id": token_id,
        "src_ip": src_ip,
        "user_agent": user_agent,
    }
