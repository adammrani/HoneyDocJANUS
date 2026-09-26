# Détection Wazuh générique des honeydocuments

## Principe

La règle Wazuh `100100` ne contient aucun nom de fichier ni aucune extension.
Elle transforme tout événement Windows `4663` situé sous le dossier partagé
du clone local en alerte candidate. Par défaut, ce dossier est :

```text
<racine-du-projet>\data\shared
```

JANUS décide ensuite si cette alerte concerne vraiment un honeydocument :

1. `wazuh_adapter.py` transforme le JSON Wazuh en `SecurityEvent` ;
2. `SqliteDecoyRegistry` charge les lignes actives de `honeydocs.db` ;
3. la corrélation compare le chemin Windows normalisé avec le chemin de chaque
   `DecoyInstance` active ;
4. un chemin enregistré produit un verdict explicable ;
5. un fichier ordinaire, même placé dans le dossier surveillé, est ignoré par
   JANUS.

La détection ne dépend donc ni du nom, ni de l'extension, ni du LLM. Le LLM
peut générer le contenu, mais l'identité du leurre vient de son enregistrement
persistant lors du déploiement.

## Formats couverts

La corrélation travaille uniquement sur l'identité et le chemin du fichier.
Elle fonctionne donc de la même façon pour DOCX, PDF, XLSX, ZIP, `.env`, YAML,
JSON et les futurs formats.

## Analyse manuelle d'une alerte

Depuis la racine du projet :

```powershell
$env:PYTHONPATH="$PWD\src"
python -m janus_v2.analyze_wazuh_alert `
  tests\fixtures\wazuh_4663_real_anonymized.json `
  data\honeydocs.db
```

La sortie JSON contient la preuve Wazuh normalisée. Si le chemin correspond à
un leurre actif, elle contient aussi la `DecoyInstance` et le verdict.

## Preuves conservées dans `SecurityEvent`

- identifiant Wazuh ;
- machine Windows ;
- domaine et utilisateur ;
- chemin ;
- action ;
- timestamp ;
- processus et PID ;
- masque d'accès ;
- identifiant de l'agent ;
- `eventRecordID` Windows.

Le JSON brut demeure dans Wazuh/OpenSearch. Lorsque la collecte automatique est
activée, JANUS en conserve aussi une copie avec le verdict dans la table SQLite
`wazuh_detections`. La contrainte unique `event_key` empêche les doublons.

## Collecte automatique Wazuh vers JANUS

Le collecteur interroge Wazuh Indexer en arrière-plan, filtre la règle
`100100`, transmet chaque alerte au pipeline de corrélation puis conserve :

- la preuve Wazuh complète ;
- l'action normalisée (`read`, `modify`, `delete`, `unknown`) ;
- le HoneyDoc reconnu, le cas échéant ;
- le score, le niveau et les raisons du verdict ;
- un curseur persistant permettant de reprendre après un redémarrage.

Une fenêtre de chevauchement relit volontairement les événements récents pour
tolérer un retard d'indexation. La déduplication SQLite garantit qu'ils ne sont
enregistrés qu'une fois. Les écritures effectuées par le processus de
déploiement JANUS pendant les premières secondes sont conservées comme preuves,
mais marquées `suppressed` afin de ne pas devenir de fausses détections.

La configuration locale se prépare sans inscrire le mot de passe dans Git :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\configure_wazuh_collector.ps1 `
  -DevelopmentTrustSelfSigned
```

Le script crée ou met à jour le fichier `.env`, déjà ignoré par Git, demande
les identifiants dans la fenêtre sécurisée Windows et sauvegarde toute ancienne
configuration. `-DevelopmentTrustSelfSigned` est réservé au laboratoire local.
Pour un déploiement réel, conservez `WAZUH_VERIFY_SSL=true` et indiquez le CA
avec `WAZUH_CA_CERT_PATH`.

Après redémarrage de l'API :

```powershell
$headers = @{ "X-JANUS-API-Key" = $env:JANUS_ADMIN_API_KEY }
Invoke-RestMethod "http://127.0.0.1:8000/wazuh/status" -Headers $headers
Invoke-RestMethod `
  "http://127.0.0.1:8000/wazuh/detections?limit=100&matched_only=true" `
  -Headers $headers
```

Une panne de l'Indexer ne bloque pas l'API : le collecteur réessaie après son
intervalle et expose la dernière erreur dans `/wazuh/status`.

## Déploiement des nouveaux leurres IA

L'endpoint `POST /generate_decoy` utilise désormais la variable
`JANUS_DEPLOY_ROOT`, dont la valeur portable par défaut est `data/shared`.
Le chemin est résolu relativement à la racine du projet.

Une requête sans `target_dir` déploie automatiquement le document dans cette
racine. Un chemin fourni par le client n'est accepté que s'il désigne la racine
ou un de ses véritables sous-dossiers. Une cible inexistante ou extérieure est
refusée avant la génération.

Le mode strict garantit que la ligne SQLite n'est créée qu'après la réussite
de la copie dans le dossier surveillé.

La SACL héritée se configure une seule fois depuis un PowerShell
administrateur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\setup_janus_audit.ps1
```

Le script est idempotent et limité par liste blanche au dossier
`<racine-du-projet>\data\shared`.

La règle Wazuh doit contenir le chemin absolu du clone Windows. Elle est
générée et installée automatiquement avec :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\configure_wazuh_rule.ps1 `
  -WazuhComposeRoot "C:\chemin\vers\wazuh-docker\single-node"
```

Le chemin absolu produit est écrit sous `data/wazuh`, qui est ignoré par Git.
Le script sauvegarde l'ancienne règle, valide la nouvelle avec
`wazuh-analysisd -t`, la restaure en cas d'échec, puis redémarre uniquement le
manager.

## Limite constatée sur les anciens leurres

Les honeydocuments déjà enregistrés sous l'ancienne racine
`C:\JANUS\shared` ne sont pas déplacés automatiquement. Ils restent dans la
base jusqu'à leur expiration, mais les nouvelles générations utilisent
`<racine-du-projet>\data\shared`.

Les anciens enregistrements ne sont pas déplacés automatiquement. Les nouveaux
documents générés utilisent le pipeline sécurisé :

- racine configurée et contrôlée par liste blanche ;
- copie stricte dans `data/shared` ;
- ligne SQLite contenant le chemin final ;
- SACL héritée appliquée au dossier surveillé.

Le générateur historique reste conservé ; seule sa sortie appelée par l'API est
renforcée pour alimenter JANUS v2.

## DOCX et macros

Les documents produits sont des fichiers `.docx` macro-free. JANUS ne demande
jamais d'activer ou de désactiver les macros. La détection repose sur l'accès
NTFS enregistré par la SACL : une ouverture normale dans Microsoft Word doit
donc générer un `4663`, même lorsque la politique Office bloque les macros et
le contenu actif.

## Sémantique des actions Windows

`4663` distingue de façon fiable les droits de lecture (`0x1`), d'écriture
(`0x2`/`0x4`) et de suppression (`0x10000`). Un déplacement hors du dossier
surveillé apparaît comme un accès de suppression sur l'ancien chemin. Une copie
ou une extraction avec `curl` apparaît comme une lecture du HoneyDoc source.
Un seul événement `4663` ne permet donc pas d'affirmer qu'une lecture était
précisément une ouverture, une copie ou un téléchargement ; cette distinction
demande une corrélation multi-événements ou une télémétrie complémentaire.
