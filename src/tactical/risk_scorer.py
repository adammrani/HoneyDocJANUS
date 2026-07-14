"""
src/tactical/risk_scorer.py
Classification des alertes Wazuh par Isolation Forest.

Lit   : scenarios/samples/siem_global_alerts.json
Écrit : scenarios/samples/suspicious_alerts.json  (anomalies → déclenchement JIT)
        scenarios/samples/normal_alerts.json       (alertes normales → ignorées)

Inspiré du pipeline ZAP/HoneyFP, adapté aux features fichiers Wazuh.
"""

import json
import pandas as pd
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────
# Tables de scoring (feature engineering)
# ─────────────────────────────────────────────

SENSITIVE_KEYWORDS = {
    "finance":     3, "payroll":  3, "salary":   3, "salaires": 3,
    "budget":      3, "tresorerie": 3, "bilan":  3,
    "hr":          2, "rh":       2, "contracts": 2, "contrats": 2,
    "legal":       2, "juridique": 2, "agreements": 2,
    "executive":   3, "direction": 3, "strategy": 3,
    "credentials": 4, "api_keys": 4, "config":   3,
    "backup":      2, "password": 4, "secret":   4,
    "general":     0, "shared":   1, "public":   0,
}

EXTENSION_RISK = {
    ".sql":  4, ".db":   4,
    ".json": 3, ".yaml": 3, ".yml":  3, ".env":  4,
    ".txt":  2, ".csv":  3, ".log":  2,
    ".xlsx": 2, ".xls":  2, ".pdf":  2,
    ".docx": 1, ".doc":  1, ".pptx": 1,
    ".py":   3, ".sh":   3, ".ps1":  3,
}

TACTIC_SCORE = {
    "Discovery":    1,
    "Collection":   2,
    "Exfiltration": 3,
    "Impact":       4,
    "Persistence":  2,
    "Lateral Movement": 3,
}

EVENT_ENCODING = {
    "added":              1,
    "modified":           2,
    "permission_changed": 3,
    "ownership_changed":  3,
    "deleted":            4,
}

# Scope normal par agent_id (doit correspondre à generate_siem_alerts.py)
AGENT_SCOPE = {
    "001": ["d:/projects/marketing", "d:/shared/general"],
    "002": ["/srv/shared/tech/", "/home/k.benali/"],
    "003": ["d:/hr/onboarding", "d:/shared/general"],
    "004": ["/srv/shared/", "/backup/"],
    "005": ["/srv/shared/", "/var/log/"],
    "006": ["d:/finance/reporting", "d:/shared/general"],
}

# ─────────────────────────────────────────────
# Extraction des features
# ─────────────────────────────────────────────

def extract_features(alert: dict) -> dict:

    # --- Groupe 1 : Temporelles ---
    ts_str = alert.get("timestamp", "").replace("+0000", "+00:00")
    try:
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        ts = datetime.now(timezone.utc)

    hour_of_day  = ts.hour
    day_of_week  = ts.weekday()
    is_outside   = int(hour_of_day < 8 or hour_of_day > 20 or day_of_week >= 5)

    # --- Groupe 2 : Volume / vélocité ---
    data_block        = alert.get("data", {}) or {}
    file_access_count = int(data_block.get("file_access_count") or 0)
    window_seconds    = int(data_block.get("window_seconds")    or 1)
    window_seconds    = max(window_seconds, 1)   # éviter division par 0
    access_rate       = round(file_access_count / window_seconds, 4)
    rule_firedtimes   = int(alert.get("rule", {}).get("firedtimes", 1))

    # --- Groupe 3 : Sensibilité du chemin ---
    raw_path = alert.get("syscheck", {}).get("path", "")
    path     = raw_path.lower().replace("\\", "/")

    path_sensitivity_score = max(
        (v for k, v in SENSITIVE_KEYWORDS.items() if k in path),
        default=0
    )

    ext              = "." + path.split(".")[-1] if "." in path else ""
    file_extension_risk = EXTENSION_RISK.get(ext, 1)
    path_depth       = len([p for p in path.split("/") if p])

    # Est-ce que l'agent accède hors de son scope habituel ?
    agent_id = alert.get("agent", {}).get("id", "001")
    scopes   = AGENT_SCOPE.get(agent_id, [])
    is_outside_scope = int(not any(path.startswith(s.lower()) for s in scopes))

    # --- Groupe 4 : Règle ---
    rule = alert.get("rule", {})
    rule_level    = int(rule.get("level", 3))
    is_custom     = int(int(rule.get("id", "0")) >= 100000)

    mitre         = rule.get("mitre", {}) or {}
    tactics       = mitre.get("tactic", []) or []
    has_mitre     = int(bool(tactics))
    mitre_encoded = max(
        (TACTIC_SCORE.get(t, 0) for t in tactics),
        default=0
    )

    # --- Groupe 5 : Type d'événement syscheck ---
    event_type    = alert.get("syscheck", {}).get("event", "modified")
    event_encoded = EVENT_ENCODING.get(event_type, 2)

    return {
        # temporelles
        "hour_of_day":              hour_of_day,
        "day_of_week":              day_of_week,
        "is_outside_business_hours": is_outside,
        # volume
        "file_access_count":        file_access_count,
        "window_seconds":           window_seconds,
        "access_rate":              access_rate,
        "rule_firedtimes":          rule_firedtimes,
        # chemin
        "path_sensitivity_score":   path_sensitivity_score,
        "path_depth":               path_depth,
        "file_extension_risk":      file_extension_risk,
        "is_outside_scope":         is_outside_scope,
        # règle
        "rule_level":               rule_level,
        "is_custom_rule":           is_custom,
        "has_mitre":                has_mitre,
        "mitre_tactic_encoded":     mitre_encoded,
        # événement
        "event_encoded":            event_encoded,
    }

# ─────────────────────────────────────────────
# Pipeline principal
# ─────────────────────────────────────────────

FEATURE_COLS = [
    "hour_of_day", "day_of_week", "is_outside_business_hours",
    "file_access_count", "window_seconds", "access_rate", "rule_firedtimes",
    "path_sensitivity_score", "path_depth", "file_extension_risk", "is_outside_scope",
    "rule_level", "is_custom_rule", "has_mitre", "mitre_tactic_encoded",
    "event_encoded",
]

def classify_wazuh_alerts(
    input_file:  str = "scenarios/samples/siem_global_alerts.json",
    output_susp: str = "scenarios/samples/suspicious_alerts.json",
    output_norm: str = "scenarios/samples/normal_alerts.json",
    contamination: float = 0.22,
):
    print(f"[*] Chargement des alertes depuis {input_file}...")
    with open(input_file, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    print(f"[*] Extraction des features ({len(FEATURE_COLS)} features × {len(alerts)} alertes)...")
    rows = [extract_features(a) for a in alerts]
    df   = pd.DataFrame(rows)

    X = df[FEATURE_COLS]

    # StandardScaler : optionnel pour IF, mais utile pour
    # lisibilité des anomaly_scores dans le dashboard
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Entraînement du modèle Isolation Forest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_features=0.8,        # sous-ensemble de features par arbre
        random_state=42,
    )
    df["ml_label"]     = model.fit_predict(X_scaled)
    df["anomaly_score"] = model.score_samples(X_scaled)   # plus négatif = plus suspect

    # Isolation Forest : -1 = anomalie (suspect), 1 = normal
    df["classification"] = df["ml_label"].apply(
        lambda x: "suspicious" if x == -1 else "normal"
    )

    # Réinjecter features + label dans les alertes originales
    for i, alert in enumerate(alerts):
        alert["_if"] = {
            "classification":  df.loc[i, "classification"],
            "anomaly_score":   round(float(df.loc[i, "anomaly_score"]), 6),
            "features":        {col: float(df.loc[i, col]) for col in FEATURE_COLS},
        }

    suspicious = [a for a in alerts if a["_if"]["classification"] == "suspicious"]
    normal     = [a for a in alerts if a["_if"]["classification"] == "normal"]

    # ── Stats ──────────────────────────────────
    susp_levels = pd.Series([a["rule"]["level"] for a in suspicious])
    norm_levels = pd.Series([a["rule"]["level"] for a in normal])

    print(f"\n[+] Classification terminée !")
    print(f"    Alertes totales   : {len(alerts)}")
    print(f"    ├─ Suspectes (→ déploiement JIT)  : {len(suspicious)}")
    print(f"    │   niveaux : {dict(susp_levels.value_counts().sort_index())}")
    print(f"    └─ Normales (→ ignorées)           : {len(normal)}")
    print(f"        niveaux : {dict(norm_levels.value_counts().sort_index())}")

    # ── Sauvegarde ─────────────────────────────
    with open(output_susp, "w", encoding="utf-8") as f:
        json.dump(suspicious, f, indent=2, ensure_ascii=False)

    with open(output_norm, "w", encoding="utf-8") as f:
        json.dump(normal, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Fichiers prêts :")
    print(f"    → {output_susp}")
    print(f"    → {output_norm}")

    return suspicious, normal

if __name__ == "__main__":
    classify_wazuh_alerts()
