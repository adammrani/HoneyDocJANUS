"""
src/detection/canarytoken_handler.py
Canarytoken creation and callback parsing.

Canarytokens are the core detection signal: a beacon embedded in every decoy
document that phones home when the document is opened. If the public
canarytokens.org service is unreachable, we fall back to a local beacon served
by our own FastAPI (`GET /ping/{uuid}`), so the system never depends on an
external service being up.

`parse_callback` turns a raw webhook payload into a normalised alert dict and
guesses the OS / browser / automation tool from the User-Agent.
"""

import uuid
from typing import Optional

import requests

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()

# User-Agent substrings that indicate automated (non-human) access.
# These are the tools an attacker or an LLM triage agent would use.
_AUTOMATION_PATTERNS = {
    "python-requests": "Python requests",
    "python-urllib": "Python urllib",
    "httpx": "httpx client",
    "aiohttp": "aiohttp client",
    "curl": "curl",
    "wget": "wget",
    "rclone": "rclone (data sync)",
    "go-http": "Go HTTP client",
    "libwww-perl": "Perl LWP",
    "okhttp": "OkHttp client",
    "langchain": "LangChain agent",
    "openai": "OpenAI client",
    "llamaindex": "LlamaIndex agent",
    "anthropic": "Anthropic client",
    "node-fetch": "Node fetch",
    "axios": "axios client",
}

_BROWSER_PATTERNS = {
    "edg/": "Microsoft Edge",
    "chrome/": "Google Chrome",
    "firefox/": "Mozilla Firefox",
    "safari/": "Safari",
    "opera": "Opera",
    "msie": "Internet Explorer",
    "trident": "Internet Explorer",
}

_OS_PATTERNS = {
    "windows nt 10": "Windows 10/11",
    "windows nt 6.3": "Windows 8.1",
    "windows": "Windows",
    "mac os x": "macOS",
    "macintosh": "macOS",
    "android": "Android",
    "iphone": "iOS",
    "ipad": "iPadOS",
    "linux": "Linux",
    "ubuntu": "Ubuntu",
}


def create_token(memo: str) -> dict:
    """
    Create a `web` Canarytoken (URL beacon) and return its identifiers.

    Returns a dict: { token_id, token_url, callback_url }.
    On any network/API failure, transparently falls back to a local beacon.
    """
    callback_url = f"{_settings.CALLBACK_BASE_URL}/alert"

    if _settings.canarytoken_configured:
        try:
            resp = requests.post(
                f"{_settings.CANARYTOKEN_SERVER}/generate",
                data={
                    "type": "web",
                    "email": _settings.CANARYTOKEN_EMAIL,
                    "memo": memo,
                    "webhook_url": callback_url,
                },
                timeout=8,
            )
            resp.raise_for_status()
            data = resp.json()
            token_id = data.get("token") or data.get("canarytoken") or uuid.uuid4().hex
            token_url = (
                data.get("token_url")
                or data.get("url")
                or f"{_settings.CANARYTOKEN_SERVER}/{token_id}/contact.png"
            )
            log.info("Canarytoken created via canarytokens.org (id=%s)", token_id)
            return {
                "token_id": token_id,
                "token_url": token_url,
                "callback_url": callback_url,
            }
        except (requests.RequestException, ValueError) as exc:
            log.warning("canarytokens.org unreachable (%s) — using local fallback", exc)

    # ── Local fallback beacon ─────────────────────────────
    token_id = uuid.uuid4().hex
    token_url = f"{_settings.CALLBACK_BASE_URL}/ping/{token_id}"
    log.info("Using local fallback Canarytoken (id=%s)", token_id)
    return {
        "token_id": token_id,
        "token_url": token_url,
        "callback_url": callback_url,
    }


def _guess_from_patterns(ua_lower: str, patterns: dict) -> Optional[str]:
    for needle, label in patterns.items():
        if needle in ua_lower:
            return label
    return None


def guess_os_and_tool(user_agent: str) -> dict:
    """
    Derive (os_guess, browser_guess, is_automated) from a User-Agent string.

    Uses the `user-agents` library when available, otherwise heuristics.
    Automated tools are reported in `browser_guess` as "Script automatisé (...)".
    """
    ua = user_agent or ""
    ua_lower = ua.lower()

    # 1) Automation tools take priority: they are the strongest attacker signal.
    tool = _guess_from_patterns(ua_lower, _AUTOMATION_PATTERNS)
    if tool:
        os_guess = _guess_from_patterns(ua_lower, _OS_PATTERNS) or "Inconnu"
        return {
            "os_guess": os_guess,
            "browser_guess": f"Script automatisé ({tool})",
            "is_automated": True,
        }

    # 2) Try the user-agents library for a rich parse of real browsers.
    try:
        from user_agents import parse as ua_parse  # lazy import

        parsed = ua_parse(ua)
        os_guess = (parsed.os.family or "Inconnu")
        if parsed.os.version_string:
            os_guess = f"{os_guess} {parsed.os.version_string}"
        browser = (parsed.browser.family or "Inconnu")
        if parsed.browser.version_string:
            browser = f"{browser} {parsed.browser.version_string}"
        return {
            "os_guess": os_guess,
            "browser_guess": browser,
            "is_automated": parsed.is_bot,
        }
    except Exception:  # noqa: BLE001 — library optional, fall back to heuristics
        pass

    # 3) Heuristic fallback.
    return {
        "os_guess": _guess_from_patterns(ua_lower, _OS_PATTERNS) or "Inconnu",
        "browser_guess": _guess_from_patterns(ua_lower, _BROWSER_PATTERNS) or "Inconnu",
        "is_automated": False,
    }


def parse_callback(payload: dict) -> dict:
    """
    Normalise a raw Canarytoken webhook payload into an alert-ready dict.

    Handles both the canarytokens.org schema and our own local `/ping` payloads.
    """
    payload = payload or {}

    token_id = (
        payload.get("token_id")
        or payload.get("token")
        or payload.get("canarytoken")
        or payload.get("memo")
    )

    src_ip = (
        payload.get("src_ip")
        or payload.get("ip")
        or payload.get("source_ip")
        or (payload.get("additional_data") or {}).get("src_ip")
    )

    user_agent = (
        payload.get("user_agent")
        or payload.get("useragent")
        or (payload.get("additional_data") or {}).get("useragent")
        or ""
    )

    geo = payload.get("geo") or {}
    geo_country = payload.get("geo_country") or geo.get("country") or payload.get("country")
    geo_city = payload.get("geo_city") or geo.get("city") or payload.get("city")

    guessed = guess_os_and_tool(user_agent)

    return {
        "token_id": token_id,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "geo_country": geo_country,
        "geo_city": geo_city,
        "os_guess": guessed["os_guess"],
        "browser_guess": guessed["browser_guess"],
        "is_automated": guessed["is_automated"],
        "raw_payload": payload,
    }
