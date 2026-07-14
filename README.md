# 🍯 Honey-Documents Dynamiques

Système de génération de **documents leurres intelligents** assisté par IA, avec
détection et profilage des attaquants via **Canarytokens**. Architecture
**standalone** : une seule machine héberge l'API (FastAPI), la base (SQLite) et
le dashboard (Streamlit).

> Stage — Adam MRANI (ENSIAS). Sujet : génération dynamique de leurres
> documentaires intelligents. Ce projet est un outil **défensif** (déception /
> Blue Team) : il détecte les accès non autorisés à des documents-appâts.

---

## Principe

On dépose dans un partage réseau des documents `.docx` crédibles générés par un
LLM (imitant le style d'un corpus interne). Chaque document embarque trois
couches (**JANUS**) :

| Couche | Rôle | Déclenchement |
|--------|------|---------------|
| **Narrative** (visible) | contenu réaliste et confidentiel | — |
| **CI1** (invisible) | instruction cachée ciblant les agents LLM de triage | `GET /ci1/{token}` |
| **CI3** (annexe) | faux credentials pointant vers l'infra leurre | SSH :2222 / HTTP :8080 |

Plus un **Canarytoken** (champ `INCLUDEPICTURE`) qui remonte IP, User-Agent, OS,
navigateur et géolocalisation dès l'ouverture du document.

---

## Pipeline

```
suspicious_alerts.json → orchestrator → threat_profiler
        → context_analyzer (+ corpus) → llm_engine (Groq)
        → coherence_check → document_assembler (JANUS)
        → canarytoken_handler → injector → .docx déposé
[attaquant ouvre] → /alert | /ci1 | decoy_infra → SQLite → dashboard
```

---

## Installation

```bash
cp .env.example .env          # puis renseignez GROQ_API_KEY / CANARYTOKEN_EMAIL
pip install -r requirements.txt
```

> Sans clé Groq, la génération LLM bascule sur un contenu de repli en français.
> Sans email Canarytoken valide, le beacon local `/ping/{token}` est utilisé.

## Pipeline offline (préparation des données)

```bash
python scenarios/synthetic_siem_alerts.py     # -> scenarios/samples/siem_global_alerts.json
python src/tactical/risk_scorer.py            # -> suspicious_alerts.json + normal_alerts.json
```

## Lancement

```bash
python src/main.py                            # API :8000 (+ decoy SSH:2222, HTTP:8080, rotation)
streamlit run src/alerting/dashboard.py       # Dashboard :8501
```

Le dashboard affiche proprement « API indisponible » si le serveur n'est pas lancé.

## Docker

```bash
docker-compose up --build                     # api (:8000) + dashboard (:8501)
```

---

## Endpoints principaux

| Méthode | Route | Rôle |
|---------|-------|------|
| POST | `/generate_decoy` | pipeline complet + dépôt d'un honeydoc |
| POST | `/alert` | réception d'un webhook Canarytoken |
| GET | `/ping/{token_id}` | beacon local (PNG 1×1) |
| GET | `/ci1/{token_id}` | callback CI1 (agent LLM détecté) |
| GET | `/alerts` | liste des alertes |
| GET | `/honeydocs` | liste des leurres déployés |
| GET | `/health` | sonde de vie |

---

## Tests

```bash
pytest -q
```

- `test_risk_scorer.py` — `extract_features` renvoie 16 features
- `test_coherence_check.py` — corpus vide ⇒ `passed=True`
- `test_injector.py` — `deploy_document` crée le `.docx` et les lignes BDD

---

## Arborescence

```
honey-documents/
├── config/        strategy_blueprint.json, risk_thresholds.yaml, ttl_policy.yaml
├── corpus/        financial/ hr/ technical/  (documents de style)
├── scenarios/     synthetic_siem_alerts.py [fourni], synthetic_events.py, samples/
├── src/
│   ├── core/          config, database (SQLite), logger
│   ├── schemas/       modèles Pydantic
│   ├── strategy/      orchestrator, threat_profiler
│   ├── tactical/      risk_scorer [fourni], watchdog, context_analyzer, llm_engine, coherence_check
│   ├── janus/         narrative_layer, ci_prompt_injection (CI1), ci_credential_trap (CI3), document_assembler
│   ├── lifecycle/     injector, rotation_manager
│   ├── detection/     canarytoken_handler, callback_listener, decoy_infra
│   ├── alerting/      alert_server (FastAPI), dashboard (Streamlit)
│   └── main.py
└── tests/
```

## Notes de sécurité

Les faux credentials (CI3) et le champ Canarytoken ne pointent que vers votre
propre infrastructure de déception. En production, faites tourner l'ensemble sur
un serveur isolé et exposez le callback via une URL publique (ngrok en dev,
reverse proxy en prod). Cet outil observe et journalise ; il ne mène aucune
action offensive.
