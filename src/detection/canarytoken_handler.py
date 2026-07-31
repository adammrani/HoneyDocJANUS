"""
src/detection/canarytoken_handler.py
Canarytoken creation and callback parsing.

Canarytokens are the core detection signal: a beacon embedded in every decoy
document that phones home when the document is opened. If the public
canarytokens.org service is unreachable, we fall back to a local beacon served
by our own FastAPI (`GET /ping/{uuid}`), so the system never depends on an
external service being up.

`parse_callback` normalise le callback et conserve clairement qu'un OS extrait
du User-Agent est une déclaration falsifiable, jamais une preuve hôte.
"""

import uuid
from typing import Optional
from urllib.parse import urlparse

import requests

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()


class CanarytokenProviderError(RuntimeError):
    """Raised when the configured Canarytokens provider rejects a request."""


def _callback_url() -> str:
    return f"{_settings.CALLBACK_BASE_URL}/alert"


def _provider_api_url(endpoint: str) -> str:
    endpoint = endpoint.lstrip("/")
    return (
        f"{_settings.CANARYTOKEN_SERVER}"
        f"{_settings.CANARYTOKEN_API_PATH}/{endpoint}"
    )


def get_canary_status() -> dict:
    """Return safe provider configuration details without exposing the email."""
    callback_host = (
        urlparse(_settings.CALLBACK_BASE_URL).hostname or ""
    ).casefold()
    return {
        "configured": _settings.canarytoken_configured,
        "provider": "canarytokens",
        "server": _settings.CANARYTOKEN_SERVER,
        "api_path_configured": bool(_settings.CANARYTOKEN_API_PATH),
        "notification": (
            "email_and_webhook"
            if _settings.CANARYTOKEN_WEBHOOK_ENABLED
            else "email"
        ),
        "webhook_enabled": _settings.CANARYTOKEN_WEBHOOK_ENABLED,
        "callback_public": callback_host not in {"localhost", "127.0.0.1", "::1"},
    }


def create_remote_token(memo: str, token_type: str = "web") -> dict:
    """Create a token through the current Canarytokens JSON API."""
    if not _settings.canarytoken_configured:
        raise CanarytokenProviderError(
            "CANARYTOKEN_EMAIL n'est pas configuré."
        )

    payload = {
        "token_type": token_type,
        "email": _settings.CANARYTOKEN_EMAIL,
        "memo": memo,
    }
    callback_url = _callback_url()
    if _settings.CANARYTOKEN_WEBHOOK_ENABLED:
        payload["webhook_url"] = callback_url

    try:
        response = requests.post(
            _provider_api_url("generate"),
            json=payload,
            timeout=_settings.CANARYTOKEN_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise CanarytokenProviderError(
            f"Échec de création Canarytoken: {exc}"
        ) from exc

    token_id = data.get("token") or data.get("canarytoken")
    token_url = data.get("token_url") or data.get("url")
    if not token_id or not token_url:
        detail = data.get("message") or data.get("error") or "réponse incomplète"
        raise CanarytokenProviderError(
            f"Le fournisseur Canarytokens a renvoyé une {detail}."
        )

    log.info(
        "Canarytoken created via provider (type=%s id=%s)",
        token_type,
        token_id,
    )
    return {
        "token_id": token_id,
        "token_url": token_url,
        "callback_url": callback_url,
        "auth_token": data.get("auth_token", ""),
        "provider": "canarytokens",
        "token_type": token_type,
        "activation_mode": (
            "automatic_email_webhook"
            if _settings.CANARYTOKEN_WEBHOOK_ENABLED
            else "automatic_email"
        ),
    }


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


def create_token(
    memo: str,
    allow_remote: bool = True,
    token_type: str = "web",
) -> dict:
    """
    Create the requested Canarytoken type and return its identifiers.

    Returns a dict: { token_id, token_url, callback_url }.
    On any network/API failure, transparently falls back to a local beacon.
    If ``allow_remote`` is false, no external service is contacted and the
    identifier is reserved as metadata only.
    """
    callback_url = _callback_url()

    if allow_remote and _settings.canarytoken_configured:
        try:
            return create_remote_token(memo=memo, token_type=token_type)
        except CanarytokenProviderError as exc:
            log.warning("%s — using local fallback", exc)

    # ── Local fallback beacon ─────────────────────────────
    token_id = uuid.uuid4().hex
    token_url = f"{_settings.CALLBACK_BASE_URL}/ping/{token_id}"
    if allow_remote:
        log.info("Using local fallback Canarytoken (id=%s)", token_id)
    else:
        log.info("Reserved local token metadata (id=%s)", token_id)
    return {
        "token_id": token_id,
        "token_url": token_url,
        "callback_url": callback_url,
        "auth_token": "",
        "provider": "local",
        "token_type": token_type,
        "activation_mode": (
            "local_fallback" if allow_remote else "metadata_only"
        ),
    }


def _guess_from_patterns(ua_lower: str, patterns: dict) -> Optional[str]:
    for needle, label in patterns.items():
        if needle in ua_lower:
            return label
    return None


def guess_os_and_tool(user_agent: str) -> dict:
    """
    Extrait un OS déclaré et l'outil depuis un User-Agent falsifiable.

    Uses the `user-agents` library when available, otherwise heuristics.
    Automated tools are reported in `browser_guess` as "Script automatisé (...)".
    """
    ua = user_agent or ""
    ua_lower = ua.lower()

    def with_os_evidence(os_guess: str, **values: object) -> dict:
        known = os_guess not in {"", "Inconnu", "Other"}
        return {
            "os_guess": os_guess if known else "Inconnu",
            "os_evidence_source": (
                "http_user_agent_claim" if known else "none"
            ),
            "os_confidence": "low" if known else "none",
            "os_scope": "requesting_client" if known else "unknown",
            **values,
        }

    # 1) Automation tools take priority: they are the strongest attacker signal.
    tool = _guess_from_patterns(ua_lower, _AUTOMATION_PATTERNS)
    if tool:
        os_guess = _guess_from_patterns(ua_lower, _OS_PATTERNS) or "Inconnu"
        return with_os_evidence(
            os_guess,
            browser_guess=f"Script automatisé ({tool})",
            is_automated=True,
        )

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
        return with_os_evidence(
            os_guess,
            browser_guess=browser,
            is_automated=parsed.is_bot,
        )
    except Exception:  # noqa: BLE001 — library optional, fall back to heuristics
        pass

    # 3) Heuristic fallback.
    return with_os_evidence(
        _guess_from_patterns(ua_lower, _OS_PATTERNS) or "Inconnu",
        browser_guess=_guess_from_patterns(ua_lower, _BROWSER_PATTERNS) or "Inconnu",
        is_automated=False,
    )


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
        "os_evidence_source": guessed["os_evidence_source"],
        "os_confidence": guessed["os_confidence"],
        "os_scope": guessed["os_scope"],
        "browser_guess": guessed["browser_guess"],
        "is_automated": guessed["is_automated"],
        "raw_payload": payload,
    }
