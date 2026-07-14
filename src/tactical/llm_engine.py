"""
src/tactical/llm_engine.py
Thin wrapper around the Groq API (Llama 3) with retry and a hardcoded fallback.

The system must never crash because the LLM API is down or unconfigured, so
`generate_content` degrades gracefully to a generic French document.
"""

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()

_MIN_CHARS = 200

_FALLBACK_CONTENT = (
    "RAPPORT INTERNE — SYNTHÈSE DE GESTION\n\n"
    "Le présent document dresse une synthèse de l'activité de la période écoulée "
    "à destination du comité de direction. Les indicateurs opérationnels restent "
    "globalement conformes aux prévisions budgétaires, malgré une pression sur les "
    "coûts d'approvisionnement.\n\n"
    "Points clés :\n"
    "- Le chiffre d'affaires progresse de 7 % en glissement annuel.\n"
    "- La marge brute se maintient à un niveau satisfaisant.\n"
    "- La trésorerie disponible permet de couvrir les échéances à court terme.\n\n"
    "Recommandations : poursuivre la maîtrise des charges d'exploitation, sécuriser "
    "le carnet de commandes du prochain trimestre et finaliser la revue des contrats "
    "fournisseurs stratégiques. Ce document est strictement confidentiel et réservé "
    "à un usage interne.\n\n"
    "Une révision détaillée des postes budgétaires sera présentée lors de la prochaine "
    "réunion mensuelle. Les responsables de service sont invités à transmettre leurs "
    "éléments d'ici la fin de semaine."
)


def _fallback(reason: str) -> str:
    log.warning("LLM fallback used: %s", reason)
    return _FALLBACK_CONTENT


def generate_content(prompt: str, max_retries: int = 3) -> str:
    """
    Generate document content from a prompt using Groq (Llama 3).

    Retries up to `max_retries` times if the result is too short. Falls back to
    a generic French document if Groq is unconfigured or unreachable.
    """
    if not _settings.groq_configured:
        return _fallback("GROQ_API_KEY not configured")

    try:
        from groq import Groq  # lazy import so the module loads without the dep
    except ImportError:
        return _fallback("groq package not installed")

    try:
        client = Groq(api_key=_settings.GROQ_API_KEY)
    except Exception as exc:  # noqa: BLE001
        return _fallback(f"Groq client init failed: {exc}")

    last_content = ""
    for attempt in range(1, max_retries + 1):
        try:
            completion = client.chat.completions.create(
                model=_settings.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=1024,
            )
            content = (completion.choices[0].message.content or "").strip()
            if len(content) >= _MIN_CHARS:
                log.info("LLM content generated (%d chars, attempt %d)", len(content), attempt)
                return content
            last_content = content
            log.warning("LLM content too short (%d chars), retrying...", len(content))
        except Exception as exc:  # noqa: BLE001 — any API error triggers retry/fallback
            log.warning("Groq call failed (attempt %d): %s", attempt, exc)

    if len(last_content) >= _MIN_CHARS:
        return last_content
    return _fallback("all retries produced insufficient content")
