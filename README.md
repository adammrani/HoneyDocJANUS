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

On dépose dans un partage surveillé des documents `.docx` ou `.xlsx` crédibles,
générés à partir d'un scénario IA. Chaque document Word embarque trois
couches (**JANUS**) :

| Couche | Rôle | Déclenchement |
|--------|------|---------------|
| **Narrative** (visible) | contenu réaliste et confidentiel | — |
| **CI1** (invisible) | instruction cachée ciblant les agents LLM de triage | `GET /ci1/{token}` |
| **CI3** (annexe) | faux credentials pointant vers l'infra leurre | SSH :2222 / HTTP :8080 |

Le champ de détection réseau Word est utilisé lorsqu'un fournisseur Canarytokens
est configuré et lorsque le client autorise le contenu distant. Les classeurs
Excel utilisent un token officiel de type `msexcel`, porté par une relation image
externe OOXML invisible. Les deux formats restent sans macro et conservent Wazuh
comme seconde couche de détection locale.

---

## Pipeline

```
suspicious_alerts.json → orchestrator → threat_profiler
        → context_analyzer (+ corpus) → llm_engine (Groq)
        → coherence_check → document_assembler | accounting_workbook
        → canarytoken_handler → injector → .docx/.xlsx déposé
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
| GET | `/generation/capabilities` | formats et détections réellement disponibles |
| POST | `/alert` | réception d'un webhook Canarytoken |
| GET | `/ping/{token_id}` | beacon local (PNG 1×1) |
| GET | `/ci1/{token_id}` | callback CI1 (agent LLM détecté) |
| GET | `/canary/status` | état du fournisseur Canarytokens et type de transport |
| POST | `/canary/test-token` | création contrôlée d'un token de test |
| GET | `/alerts` | liste des alertes |
| GET | `/honeydocs` | liste des leurres déployés |
| GET | `/wazuh/status` | état du collecteur automatique Wazuh |
| GET | `/wazuh/detections` | événements Wazuh corrélés et verdicts JANUS |
| GET | `/health` | sonde de vie |

---

## Tests

```bash
pytest -q
```

- `test_risk_scorer.py` — `extract_features` renvoie 16 features
- `test_coherence_check.py` — corpus vide ⇒ `passed=True`
- `test_injector.py` — `deploy_document` crée le `.docx` et les lignes BDD
- `test_accounting_workbook.py` — journal équilibré, structure XLSX et absence de macro

## Génération Excel comptable

Le format `xlsx` est disponible pour `financial_report`. Exemple PowerShell :

```powershell
$body = @{
  doc_type = "financial_report"
  output_format = "xlsx"
  scenario = "financial_accounting"
  company_name = "Atlas Conseil & Industrie SA"
  fiscal_year = 2026
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/generate_decoy" `
  -ContentType "application/json" `
  -Body $body
```

Le classeur généré contient une synthèse IA, un journal en partie double, une
balance, un compte de résultat, un bilan contrôlé et un budget mensuel avec
graphique. Les montants sont générés par du code vérifiable : l'IA ne décide pas
des égalités comptables. Le fichier est un `.xlsx` standard sans VBA ni macro.
Lorsque Canarytokens est configuré, une image distante transparente de 1×1 pixel
est référencée dans le paquet OOXML : son chargement déclenche l'alerte distante,
sans modifier le contenu visible du classeur.

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
│   ├── janus/         couches DOCX + generators/accounting_workbook
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

## Télémétrie forensique Windows/Linux

La version 1.4 ajoute les routes `GET /telemetry/status` et
`GET /telemetry/signals`, les événements Windows `4624/4663/4688/5145`, les
événements Sysmon `1/3/11/22/23/26` et les commandes Linux capturées par
`auditd/execve`. Voir `docs/forensic-telemetry.md` pour l'installation, les
champs fiables et les limites d'interprétation.

## Détection Wazuh locale (JANUS v2)

Les nouveaux honeydocuments sont déployés par défaut dans `data/shared`, à
l'intérieur du clone local. Le dossier et les documents générés sont ignorés
par Git.

Depuis un PowerShell administrateur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\setup_janus_audit.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\test_windows_forensics.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\configure_wazuh_rule.ps1 `
  -WazuhComposeRoot "C:\chemin\vers\wazuh-docker\single-node"
```

La première commande ajoute la SACL héritée. La seconde génère une règle Wazuh
pour le chemin absolu de ce clone et redémarre uniquement le manager après
validation.

Les `.docx` générés ne contiennent aucune macro. Leur ouverture normale dans
Word est détectée par l'audit Windows, indépendamment des réglages de macros.

Pour activer le transport automatique des alertes `100100` vers JANUS :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\configure_wazuh_collector.ps1 `
  -DevelopmentTrustSelfSigned
```

Le mot de passe Indexer est demandé de façon interactive et stocké uniquement
dans `.env`, qui est ignoré par Git. En production, utilisez le certificat CA
avec `WAZUH_VERIFY_SSL=true` au lieu de l'option de laboratoire ci-dessus.

Après redémarrage de l'API, consultez `/wazuh/status` et
`/wazuh/detections`. Le collecteur reprend grâce à un curseur SQLite, tolère les
retards d'indexation et déduplique chaque événement.
