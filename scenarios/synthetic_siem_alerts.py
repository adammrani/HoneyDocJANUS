"""
generate_siem_alerts.py
Génère un fichier siem_global_alerts.json simulant de vraies alertes Wazuh
basées sur des interactions fichiers (syscheck + règles custom).

Distribution des niveaux (200 alertes) :
  3–4   Informational  : 40
  5–7   Low            : 60
  8–10  Medium         : 50
  11–13 High           : 35
  14–15 Critical       : 15

Usage :
  pip install faker
  python generate_siem_alerts.py
  -> scenarios/samples/siem_global_alerts.json
"""

import json
import hashlib
import random
import uuid
import os
from datetime import datetime, timedelta, timezone
from faker import Faker

fake = Faker("fr_FR")
random.seed(42)

# ─────────────────────────────────────────────
# Données statiques réalistes
# ─────────────────────────────────────────────

AGENTS = [
    {"id": "001", "name": "WORKSTATION-TAHIRI",  "ip": "192.168.1.42", "os": "Windows 10 Pro"},
    {"id": "002", "name": "WORKSTATION-BENALI",  "ip": "192.168.1.55", "os": "Windows 11"},
    {"id": "003", "name": "WORKSTATION-ALAMI",   "ip": "192.168.1.63", "os": "Windows 10 Pro"},
    {"id": "004", "name": "SRV-FILES-01",         "ip": "192.168.1.10", "os": "Ubuntu 22.04"},
    {"id": "005", "name": "SRV-FILES-02",         "ip": "192.168.1.11", "os": "Ubuntu 22.04"},
    {"id": "006", "name": "WORKSTATION-CHAKIR",  "ip": "192.168.1.78", "os": "Windows 10 Pro"},
]

USERS = {
    "001": {"name": "m.tahiri",  "scope": ["D:/Projects/Marketing", "D:/Shared/General"]},
    "002": {"name": "k.benali",  "scope": ["/srv/shared/tech/", "/home/k.benali/"]},
    "003": {"name": "s.alami",   "scope": ["D:/HR/Onboarding", "D:/Shared/General"]},
    "004": {"name": "svc_backup","scope": ["/srv/shared/", "/backup/"]},
    "005": {"name": "svc_audit", "scope": ["/srv/shared/", "/var/log/"]},
    "006": {"name": "y.chakir",  "scope": ["D:/Finance/Reporting", "D:/Shared/General"]},
}

# Chemins sensibles Windows
WIN_SENSITIVE_PATHS = [
    "D:/Finance/Reporting/Q2_2026/",
    "D:/Finance/Payroll/",
    "D:/Finance/Budget/",
    "D:/HR/Contracts/",
    "D:/HR/Salaries/",
    "D:/Legal/Agreements/",
    "D:/Legal/IP/",
    "D:/Executive/Strategy/",
]

# Chemins sensibles Linux
LINUX_SENSITIVE_PATHS = [
    "/srv/shared/finance/",
    "/srv/shared/hr/",
    "/srv/shared/legal/",
    "/srv/shared/executive/",
]

# Noms de fichiers réalistes par catégorie
FILE_NAMES = {
    "finance": [
        "budget_2026.xlsx", "rapport_Q2_2026.docx", "bilan_comptable.xlsx",
        "previsions_tresorerie.xlsx", "audit_interne_2025.pdf",
        "factures_fournisseurs_juin.xlsx", "plan_financier_H2.pptx",
        "salaires_cadres.xlsx", "notes_frais_mai.pdf",
    ],
    "hr": [
        "contrat_CDI_tahiri.docx", "liste_employes_2026.xlsx",
        "evaluations_annuelles.docx", "plan_recrutement.pptx",
        "registre_disciplinaire.pdf", "organigramme_2026.xlsx",
        "grille_salaires.xlsx", "politique_conges.docx",
    ],
    "legal": [
        "accord_NDA_client_X.pdf", "brevet_technologie_2025.docx",
        "contrat_fournisseur_logistique.pdf", "cgv_2026.docx",
        "accord_partenariat.pdf", "litige_client_2024.docx",
    ],
    "technical": [
        "architecture_systeme_v3.docx", "rapport_audit_securite.pdf",
        "schema_reseau_interne.vsdx", "credentials_staging.txt",
        "api_keys_backup.json", "config_prod.yaml",
        "backup_db_config.sql", "deploy_notes.md",
    ],
    "general": [
        "reunion_comite_juin.docx", "compte_rendu_board.pdf",
        "planning_projet_2026.xlsx", "roadmap_produit.pptx",
        "rapport_hebdo_IT.docx", "note_interne_securite.pdf",
    ],
}

# ─────────────────────────────────────────────
# Règles Wazuh (réelles + custom)
# ─────────────────────────────────────────────

RULES = {
    # Niveau 3-4 : Informational
    3: [
        {"id": "554",    "description": "File added to the system.",               "groups": ["ossec", "syscheck", "syscheck_entry_added"]},
        {"id": "553",    "description": "File deleted.",                            "groups": ["ossec", "syscheck", "syscheck_entry_deleted"]},
    ],
    4: [
        {"id": "552",    "description": "File permissions changed.",                "groups": ["ossec", "syscheck"]},
        {"id": "555",    "description": "File ownership changed.",                  "groups": ["ossec", "syscheck"]},
    ],
    # Niveau 5-7 : Low
    5: [
        {"id": "554",    "description": "File added to the system.",               "groups": ["ossec", "syscheck", "syscheck_entry_added"]},
        {"id": "550",    "description": "Integrity checksum changed.",              "groups": ["ossec", "syscheck", "syscheck_integrity_changed"]},
    ],
    6: [
        {"id": "550",    "description": "Integrity checksum changed.",              "groups": ["ossec", "syscheck", "syscheck_integrity_changed"]},
        {"id": "556",    "description": "Audit policy changed.",                    "groups": ["ossec", "syscheck"]},
    ],
    7: [
        {"id": "550",    "description": "Integrity checksum changed.",              "groups": ["ossec", "syscheck"]},
        {"id": "553",    "description": "File deleted from monitored directory.",   "groups": ["ossec", "syscheck", "syscheck_entry_deleted"]},
    ],
    # Niveau 8-10 : Medium
    8: [
        {"id": "100110", "description": "Multiple files modified in short timeframe.",           "groups": ["custom", "syscheck", "anomaly"]},
        {"id": "100111", "description": "File access outside monitored working hours.",          "groups": ["custom", "syscheck", "time_anomaly"]},
    ],
    9: [
        {"id": "100112", "description": "Sensitive directory accessed by unauthorized user.",    "groups": ["custom", "syscheck", "access_control"]},
        {"id": "100113", "description": "High volume of file reads in monitored directory.",     "groups": ["custom", "syscheck", "anomaly"]},
    ],
    10: [
        {"id": "100114", "description": "Abnormal file access rate detected.",                   "groups": ["custom", "syscheck", "anomaly"],
         "mitre": {"id": ["T1083"], "tactic": ["Discovery"], "technique": ["File and Directory Discovery"]}},
        {"id": "100115", "description": "User accessed directory outside normal scope.",         "groups": ["custom", "syscheck", "access_control"],
         "mitre": {"id": ["T1083"], "tactic": ["Discovery"], "technique": ["File and Directory Discovery"]}},
    ],
    # Niveau 11-13 : High
    11: [
        {"id": "100116", "description": "Recursive file scan on sensitive directories.",         "groups": ["custom", "syscheck", "anomaly"],
         "mitre": {"id": ["T1083"], "tactic": ["Discovery"], "technique": ["File and Directory Discovery"]}},
        {"id": "100117", "description": "Mass file access across multiple sensitive paths.",     "groups": ["custom", "syscheck", "lateral_movement"],
         "mitre": {"id": ["T1083", "T1039"], "tactic": ["Discovery", "Collection"], "technique": ["File and Directory Discovery", "Data from Network Shared Drive"]}},
    ],
    12: [
        {"id": "100118", "description": "Possible data staging detected - bulk file copy.",      "groups": ["custom", "syscheck", "exfiltration"],
         "mitre": {"id": ["T1074"], "tactic": ["Collection"], "technique": ["Data Staged"]}},
        {"id": "100119", "description": "Sensitive files accessed after hours - high volume.",   "groups": ["custom", "syscheck", "anomaly"],
         "mitre": {"id": ["T1083", "T1074"], "tactic": ["Discovery", "Collection"], "technique": ["File and Directory Discovery", "Data Staged"]}},
    ],
    13: [
        {"id": "100120", "description": "Abnormal access pattern matching insider threat profile.", "groups": ["custom", "syscheck", "insider_threat"],
         "mitre": {"id": ["T1083", "T1074", "T1048"], "tactic": ["Discovery", "Collection", "Exfiltration"], "technique": ["File and Directory Discovery", "Data Staged", "Exfiltration Over Alternative Protocol"]}},
    ],
    # Niveau 14-15 : Critical
    14: [
        {"id": "100121", "description": "Suspected exfiltration preparation - mass sensitive file access.", "groups": ["custom", "syscheck", "exfiltration", "critical"],
         "mitre": {"id": ["T1048", "T1074"], "tactic": ["Collection", "Exfiltration"], "technique": ["Data Staged", "Exfiltration Over Alternative Protocol"]}},
        {"id": "100122", "description": "Possible ransomware behavior - mass file modification.",           "groups": ["custom", "syscheck", "ransomware", "critical"],
         "mitre": {"id": ["T1486"], "tactic": ["Impact"], "technique": ["Data Encrypted for Impact"]}},
    ],
    15: [
        {"id": "100123", "description": "Critical: bulk deletion of sensitive files detected.",             "groups": ["custom", "syscheck", "ransomware", "critical"],
         "mitre": {"id": ["T1485", "T1486"], "tactic": ["Impact"], "technique": ["Data Destruction", "Data Encrypted for Impact"]}},
    ],
}

SYSCHECK_EVENTS = ["added", "modified", "deleted", "permission_changed", "ownership_changed"]

# ─────────────────────────────────────────────
# Fonctions utilitaires
# ─────────────────────────────────────────────

def fake_hash(length: int) -> str:
    return hashlib.md5(uuid.uuid4().bytes).hexdigest()[:length]

def fake_sha256() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()

def fake_timestamp(hours_back: int = 168) -> str:
    """Génère un timestamp dans les 7 derniers jours, parfois hors heures ouvrables."""
    base = datetime.now(timezone.utc) - timedelta(hours=random.randint(0, hours_back))
    if random.random() < 0.25:  # 25% des événements hors heures ouvrables
        base = base.replace(hour=random.choice([0, 1, 2, 3, 22, 23]))
    return base.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

def pick_path(agent_id: str, level: int) -> str:
    """Choisit un chemin selon l'agent et la sévérité."""
    agent = AGENTS[int(agent_id) - 1]
    is_windows = "Windows" in agent["os"]

    if level <= 7:
        # Chemin dans le scope normal de l'utilisateur
        user = USERS[agent_id]
        base = random.choice(user["scope"])
        category = random.choice(list(FILE_NAMES.keys()))
        filename = random.choice(FILE_NAMES[category])
        return f"{base}/{filename}" if not is_windows else f"{base}\\{filename}"
    else:
        # Chemin sensible HORS scope normal
        if is_windows:
            base = random.choice(WIN_SENSITIVE_PATHS)
        else:
            base = random.choice(LINUX_SENSITIVE_PATHS)
        category = random.choice(["finance", "hr", "legal", "technical"])
        filename = random.choice(FILE_NAMES[category])
        return f"{base}{filename}"

def make_syscheck(path: str, event: str) -> dict:
    sc = {
        "path": path,
        "mode": random.choice(["scheduled", "realtime", "whodata"]),
        "event": event,
    }
    if event in ("modified", "permission_changed", "ownership_changed"):
        sc.update({
            "size_before": str(random.randint(1024, 5000000)),
            "size_after":  str(random.randint(1024, 5000000)),
            "md5_before":  fake_hash(32),
            "md5_after":   fake_hash(32),
            "sha1_before": fake_hash(40),
            "sha1_after":  fake_hash(40),
            "sha256_before": fake_sha256(),
            "sha256_after":  fake_sha256(),
            "mtime_before":  fake_timestamp(200),
            "mtime_after":   fake_timestamp(1),
        })
    elif event == "added":
        sc.update({
            "size_after":    str(random.randint(1024, 5000000)),
            "md5_after":     fake_hash(32),
            "sha1_after":    fake_hash(40),
            "sha256_after":  fake_sha256(),
            "mtime_after":   fake_timestamp(1),
        })
    elif event == "deleted":
        sc.update({
            "size_before":   str(random.randint(1024, 5000000)),
            "md5_before":    fake_hash(32),
            "sha1_before":   fake_hash(40),
            "sha256_before": fake_sha256(),
        })

    if event in ("permission_changed",):
        sc["perm_before"] = random.choice(["100644", "100755", "100600"])
        sc["perm_after"]  = random.choice(["100777", "100644", "100755"])

    uid = str(random.randint(1000, 1010))
    sc["uid_after"]   = uid
    sc["gid_after"]   = uid
    sc["uname_after"] = fake.user_name()
    sc["gname_after"] = "users"
    sc["inode_after"] = random.randint(100000, 9999999)
    return sc

def make_full_log(path: str, event: str, rule_desc: str) -> str:
    return (
        f"Wazuh syscheck alert: {rule_desc}\n"
        f"File: '{path}'\n"
        f"Event: {event}\n"
        f"Mode: scheduled\n"
    )

def make_alert(level: int) -> dict:
    agent = random.choice(AGENTS)
    agent_id = agent["id"]
    rule_data = random.choice(RULES[level])
    ts = fake_timestamp()
    event_type = random.choice(SYSCHECK_EVENTS)

    # Pour les niveaux critiques, forcer des événements pertinents
    if level >= 12:
        event_type = random.choice(["modified", "deleted", "added"])
    elif level >= 10:
        event_type = random.choice(["modified", "added"])

    path = pick_path(agent_id, level)

    rule = {
        "level": level,
        "description": rule_data["description"],
        "id": rule_data["id"],
        "firedtimes": random.randint(1, 20 if level >= 10 else 3),
        "mail": level >= 12,
        "groups": rule_data["groups"],
    }
    if "mitre" in rule_data:
        rule["mitre"] = rule_data["mitre"]

    alert = {
        "timestamp": ts,
        "@timestamp": ts,
        "rule": rule,
        "agent": {
            "id": agent_id,
            "name": agent["name"],
            "ip": agent["ip"],
        },
        "manager": {
            "name": "wazuh-manager-01"
        },
        "cluster": {
            "name": "wazuh",
            "node": "wazuh.manager"
        },
        "id": f"{int(datetime.now().timestamp())}.{random.randint(10000, 99999)}",
        "full_log": make_full_log(path, event_type, rule_data["description"]),
        "syscheck": make_syscheck(path, event_type),
        "decoder": {
            "name": "syscheck_integrity_changed"
            if event_type == "modified"
            else "syscheck_new_entry"
            if event_type == "added"
            else "syscheck_deleted_entry"
            if event_type == "deleted"
            else "syscheck_integrity_changed"
        },
        "location": "syscheck",
        "input": {
            "type": "log"
        },
    }

    # Pour les alertes high/critical, ajouter un contexte d'accès multiple
    if level >= 10:
        alert["data"] = {
            "audit": {
                "file": {"name": path},
                "exe": random.choice([
                    "C:/Windows/explorer.exe",
                    "C:/Program Files/Microsoft Office/root/Office16/EXCEL.EXE",
                    "/usr/bin/cp",
                    "/bin/cat",
                    "C:/Windows/System32/cmd.exe",
                    "/usr/bin/rsync",
                ]),
                "type": "PATH",
            },
            "file_access_count": random.randint(20, 200) if level >= 10 else None,
            "window_seconds": random.randint(30, 300) if level >= 10 else None,
        }
        # Nettoyer les None
        alert["data"]["audit"] = {
            k: v for k, v in alert["data"]["audit"].items() if v is not None
        }
        alert["data"] = {k: v for k, v in alert["data"].items() if v is not None}

    return alert

# ─────────────────────────────────────────────
# Génération
# ─────────────────────────────────────────────

DISTRIBUTION = {
    3: 20, 4: 20,       # 40 informational
    5: 20, 6: 20, 7: 20,  # 60 low
    8: 17, 9: 17, 10: 16, # 50 medium
    11: 12, 12: 12, 13: 11, # 35 high
    14: 8, 15: 7,        # 15 critical
}

def generate(output_path: str):
    alerts = []
    for level, count in DISTRIBUTION.items():
        for _ in range(count):
            alerts.append(make_alert(level))

    # Tri par timestamp pour simuler un flux réel
    alerts.sort(key=lambda a: a["timestamp"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(alerts)} alertes générées → {output_path}")
    print(f"     Distribution : { {l: DISTRIBUTION[l] for l in sorted(DISTRIBUTION)} }")

if __name__ == "__main__":
    generate("scenarios/samples/siem_global_alerts.json")
