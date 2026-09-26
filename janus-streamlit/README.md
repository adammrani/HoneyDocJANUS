# JANUS Evidence Hub — Python + Streamlit

Cette version reconstruit JANUS autour d’un dashboard Streamlit et d’une API FastAPI. Elle génère des honey-documents DOCX synthétiques, conserve les événements bruts dans SQLite et affiche une timeline qui sépare faits, déclarations externes, tests contrôlés et inférences.

La version web précédente reste intacte dans `../janus-next`. Les éléments fiables du projet historique ont été repris : génération IA avec repli déclaré, adaptateur Canary officiel, normalisation Wazuh et corrélation par clés fortes.

## Démarrer

Prérequis : Python 3.11 ou plus récent.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

Ouvrez ensuite [http://127.0.0.1:8501](http://127.0.0.1:8501).

Le mode par défaut fonctionne sans clé : le contenu provient d’un gabarit local explicitement indiqué dans le registre. Le bouton **Générer le honeydoc** produit et télécharge un vrai DOCX sans macro.

## Ce qui fonctionne sans service externe

- dashboard Streamlit ;
- génération et téléchargement DOCX ;
- pixel JANUS local ;
- mode double capteur avec une URL Canary existante ;
- stockage brut puis normalisé dans SQLite ;
- tests contrôlés pixel et Wazuh 4663 ;
- ingestion Wazuh protégée ;
- normalisation 4624, 4663, 4688, 5145 et Sysmon 1/3/11/22/23/26 ;
- corrélation 4663 + 4688/Sysmon 1 par hôte, Logon ID et fenêtre de cinq secondes.

Les données locales sont créées sous `data/` et exclues de Git.

## Capteurs et garanties

| Mécanisme | Nom de source | Ce qu’il prouve | Ce qu’il ne prouve pas seul |
| --- | --- | --- | --- |
| Pixel JANUS | `janus_pixel` | Une requête HTTP a atteint cette instance | Une ouverture humaine ou l’identité de la personne |
| Canary distant | `canary` | Le fournisseur a déclaré un contact | La machine locale sans autre clé de corrélation |
| Wazuh 4663 | `wazuh` | Le droit d’accès au fichier a été utilisé | Ouverture, copie ou indexation sans télémétrie complémentaire |
| Wazuh 4663 + 4688/Sysmon 1 | `wazuh` corroboré | Fichier et processus liés à la même session forte | L’intention de l’utilisateur |
| Fixture du dashboard | `controlled` | Le pipeline fonctionne | Un événement réel de sécurité |

Deux mécanismes différents ne portent jamais le même nom ni le même niveau de garantie. Il n’existe aucun repli silencieux de Canary vers le pixel JANUS.

## Configuration facultative

Copiez `.env.example` vers `.env` et renseignez uniquement les services nécessaires.

### IA compatible OpenAI/Groq

```text
AI_MODE=auto
AI_API_URL=https://api.groq.com/openai/v1/chat/completions
AI_API_KEY=...
AI_MODEL=...
```

`api` rend l’API obligatoire. `auto` autorise un repli local, mais l’artefact est alors marqué `local-template:fallback-…` et non `ai-api`.

### Deux machines sur le réseau local

```text
JANUS_API_HOST=0.0.0.0
JANUS_STREAMLIT_HOST=0.0.0.0
JANUS_PUBLIC_BASE_URL=http://192.168.1.25:8000
JANUS_ADMIN_API_KEY=une-valeur-longue
```

Remplacez l’adresse IP par celle de la machine JANUS et autorisez les ports 8000 et 8501 uniquement sur le réseau de laboratoire. Les nouveaux DOCX utiliseront l’adresse publique configurée ; un ancien DOCX n’est pas modifié rétroactivement.

### Canarytokens

Le mode `canary_remote` demande seulement l’URL HTTP d’un token déjà créé. L’adaptateur officiel est activé lorsque `CANARY_ALERT_EMAIL` ou `CANARY_WEBHOOK_URL` est renseigné. Les références de gestion restent dans la base locale privée et ne sont jamais renvoyées par l’API publique.

L’API officielle conservée depuis la passation est isolée dans `janus/canary.py` et doit être validée par un test réel avant une démonstration, car le contrat du service externe peut évoluer.

### Wazuh

Consultez [docs/WAZUH.md](docs/WAZUH.md). L’ingestion HTTP réelle exige `WAZUH_INGEST_SECRET`. La collecte automatique de l’Indexer reste facultative.

## Tester

```powershell
python -m compileall -q .
python -m pytest
```

Les tests couvrent l’origine du contenu, la structure OOXML, l’absence de macro, les capteurs séparés, la protection Wazuh, la conservation brute et la corroboration 4663/4688.

## Documents de conception

- [Cahier des charges](docs/CAHIER_DES_CHARGES.md)
- [Intégration Wazuh](docs/WAZUH.md)

