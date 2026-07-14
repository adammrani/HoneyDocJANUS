"""
scenarios/synthetic_events.py
Minimal generator of simulated filesystem events.

Writes a handful of fake FS events to data/fs_events.jsonl so the watchdog
pipeline and dashboards have sample data without needing a live share.

Usage:
    python scenarios/synthetic_events.py --count 20
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

_EVENTS = ["created", "modified", "deleted", "moved"]
_PATHS = [
    "/srv/shared/finance/rapport_Q2_2026.docx",
    "/srv/shared/hr/grille_salaires.xlsx",
    "/srv/shared/technical/config_prod.yaml",
    "D:/Finance/Payroll/salaires_cadres.xlsx",
    "D:/HR/Contracts/contrat_CDI.docx",
]


def generate(count: int, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    now = datetime.now(timezone.utc)
    with open(output_path, "w", encoding="utf-8") as f:
        for i in range(count):
            record = {
                "timestamp": (now - timedelta(minutes=i * 3)).isoformat(),
                "event_type": random.choice(_EVENTS),
                "src_path": random.choice(_PATHS),
                "dest_path": "",
                "is_directory": False,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"[OK] {count} synthetic FS events -> {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--output", default="data/fs_events.jsonl")
    args = parser.parse_args()
    generate(args.count, args.output)
