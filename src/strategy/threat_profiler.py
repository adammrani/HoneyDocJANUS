"""
src/strategy/threat_profiler.py
Strategy level: derive a threat profile from the orchestration plan.

The number of suspicious alerts drives a threat level (medium / high / critical)
which in turn decides whether the full JANUS layering (CI1 + CI3) should be
enabled for deployed decoys.
"""

import os

import yaml

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()


def _load_escalation() -> dict:
    path = os.path.join(_settings.CONFIG_DIR, "risk_thresholds.yaml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("profile_escalation", {"medium": 1, "high": 8, "critical": 20})
    except (OSError, yaml.YAMLError):
        return {"medium": 1, "high": 8, "critical": 20}


def build_profile(orchestration_plan: dict) -> dict:
    """
    Return a threat profile dict:
        {
          "threat_level": "medium" | "high" | "critical",
          "total_suspicious": int,
          "dominant_decoy_type": str,
          "enable_janus": bool,
          "enable_ci3": bool,
          "recommended_ttl_hours": int,
        }
    """
    total = int(orchestration_plan.get("total_suspicious", 0))
    dominant = orchestration_plan.get("dominant_decoy_type", "financial_report")
    esc = _load_escalation()

    if total >= esc.get("critical", 20):
        level = "critical"
    elif total >= esc.get("high", 8):
        level = "high"
    else:
        level = "medium"

    enable_janus = level in ("high", "critical")
    enable_ci3 = level == "critical"
    ttl = {"medium": 96, "high": 72, "critical": 48}[level]

    profile = {
        "threat_level": level,
        "total_suspicious": total,
        "dominant_decoy_type": dominant,
        "enable_janus": enable_janus,
        "enable_ci3": enable_ci3,
        "recommended_ttl_hours": ttl,
    }
    log.info("Threat profile: level=%s janus=%s ci3=%s", level, enable_janus, enable_ci3)
    return profile
