"""
src/strategy/orchestrator.py
Strategy level: turn suspicious alerts into a deployment plan.

Reads `suspicious_alerts.json` (produced by risk_scorer.py), inspects the file
paths and MITRE tactics involved, and decides which decoy type is most relevant
to deploy and where.
"""

import json
import os
from collections import Counter

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()

# Keyword -> decoy type mapping used to classify each suspicious path.
_TYPE_KEYWORDS = {
    "financial_report": ["finance", "payroll", "salaire", "salaries", "budget",
                          "tresorerie", "bilan", "reporting"],
    "hr_document": ["hr", "rh", "contract", "contrat", "onboarding", "employe",
                    "recrutement"],
    "technical_config": ["config", "credential", "api_key", "backup", "deploy",
                         "secret", ".yaml", ".env", ".sql"],
}

_DEFAULT_TYPE = "financial_report"


def _classify_path(path: str) -> str:
    p = (path or "").lower().replace("\\", "/")
    scores = {t: sum(1 for kw in kws if kw in p) for t, kws in _TYPE_KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else _DEFAULT_TYPE


def orchestrate(alerts_path: str = "") -> dict:
    """
    Build a deployment plan from suspicious alerts.

    Returns:
        {
          "dominant_decoy_type": str,
          "distribution": {type: count},
          "target_paths": [str, ...],   # deduplicated sensitive directories
          "total_suspicious": int,
        }
    """
    path = alerts_path or os.path.join(_settings.SAMPLES_DIR, "suspicious_alerts.json")

    if not os.path.exists(path):
        log.warning("No suspicious_alerts.json at %s — empty plan", path)
        return {
            "dominant_decoy_type": _DEFAULT_TYPE,
            "distribution": {},
            "target_paths": [],
            "total_suspicious": 0,
        }

    with open(path, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    type_counter: Counter = Counter()
    target_dirs: list[str] = []

    for alert in alerts:
        file_path = (alert.get("syscheck", {}) or {}).get("path", "")
        decoy_type = _classify_path(file_path)
        type_counter[decoy_type] += 1

        directory = os.path.dirname(file_path.replace("\\", "/"))
        if directory and directory not in target_dirs:
            target_dirs.append(directory)

    dominant = type_counter.most_common(1)[0][0] if type_counter else _DEFAULT_TYPE

    plan = {
        "dominant_decoy_type": dominant,
        "distribution": dict(type_counter),
        "target_paths": target_dirs,
        "total_suspicious": len(alerts),
    }
    log.info(
        "Orchestration plan: dominant=%s total=%d distribution=%s",
        dominant, len(alerts), plan["distribution"],
    )
    return plan


if __name__ == "__main__":
    print(json.dumps(orchestrate(), indent=2, ensure_ascii=False))
