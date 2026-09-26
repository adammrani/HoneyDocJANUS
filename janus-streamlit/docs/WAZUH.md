# Intégration Wazuh

JANUS accepte deux chemins d’entrée : ingestion HTTP protégée ou lecture facultative de Wazuh Indexer. Dans les deux cas, le JSON original est stocké avant normalisation.

## 1. Préparer Windows

Depuis un PowerShell administrateur :

```powershell
.\scripts\configure_windows_forensics.ps1 -IncludeCommandLine
.\scripts\setup_janus_audit.ps1
```

Le premier script sauvegarde la stratégie d’audit puis active 4624, 4663, 5145 et 4688. L’option `-IncludeCommandLine` améliore la preuve processus, mais les commandes peuvent contenir des données sensibles : limitez l’accès aux événements.

Le second script ajoute une SACL uniquement sur `data\generated`. Il refuse implicitement toute autre racine puisqu’il n’accepte aucun chemin fourni par l’utilisateur.

## 2. Générer les règles Wazuh

```powershell
.\scripts\render_wazuh_rules.ps1
```

Le fichier rendu est `data\janus_rules.xml`. Copiez-le vers `/var/ossec/etc/rules/local_rules.xml` sur le manager, validez avec `wazuh-analysisd -t`, puis redémarrez le manager. La racine Windows absolue est échappée automatiquement.

Règles conservées de la version historique :

- 100100 : accès 4663 dans la racine JANUS ;
- 100101 : lecture candidate ;
- 100102 : modification ;
- 100103 : suppression ;
- 100104 : lecteur Office/PDF ;
- 100110 : ouverture de session 4624 ;
- 100111 : accès SMB 5145 ;
- 100112 : création de processus 4688 pertinente.

## 3. Ingestion HTTP

Dans `.env` :

```text
WAZUH_INGEST_SECRET=une-valeur-longue-et-aleatoire
```

Envoyez le JSON vers `POST /api/events/wazuh` avec l’en-tête `X-JANUS-Wazuh-Secret`. Une valeur absente provoque `503`; une mauvaise valeur provoque `401` et aucun événement n’est enregistré.

## 4. Collecte automatique de l’Indexer

```text
WAZUH_AUTO_COLLECT=true
WAZUH_INDEXER_URL=https://wazuh-indexer.example:9200
WAZUH_INDEXER_USERNAME=janus-reader
WAZUH_INDEXER_PASSWORD=...
WAZUH_INDEX_PATTERN=wazuh-alerts-4.x-*
WAZUH_VERIFY_SSL=true
```

Utilisez un compte en lecture seule limité aux indices nécessaires. Gardez la validation TLS active et déployez le certificat d’autorité dans l’environnement système.

Le collecteur parcourt par pages toutes les alertes qui possèdent un identifiant d’événement Windows. Les identifiants pris en charge sont normalisés ; les autres sont tout de même conservés avec `normalization_pending`. Une petite reprise sur le dernier horodatage est volontaire et les doublons sont éliminés dans SQLite par la clé source.

Wazuh documente les alertes dans les indices `wazuh-alerts-*` et leur consultation via l’API Indexer :

- https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html

## 5. Limites

- 4663 prouve l’utilisation d’un droit d’accès, pas l’intention humaine ;
- antivirus, indexeur et aperçu peuvent produire un accès ;
- le Logon ID doit être borné dans le temps ;
- 5145 ne suffit pas à attribuer une personne physique ;
- l’absence d’événement ne prouve pas l’absence d’action ;
- `wazuh-alerts-*` ne contient que les événements ayant déclenché une règle ; utilisez les archives si votre protocole de laboratoire exige tous les événements.
