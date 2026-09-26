# Télémétrie forensique JANUS

JANUS sépare trois niveaux : la détection HoneyDoc directe, la télémétrie de
contexte utilisée pour reconstruire une session, et les inférences. Un champ
absent reste inconnu ; il n'est jamais complété artificiellement.

## Sources et limites

| Source | Information observée | Limite |
|---|---|---|
| Windows 4663 + SACL | chemin, compte, processus et droit de lecture, écriture ou suppression utilisé | une lecture ne prouve ni l'affichage complet ni un téléchargement |
| Windows 4624 | compte, Logon ID, type de connexion, IP/port si Windows les fournit | une session locale ne fournit pas d'IP distante |
| Windows 5145 | accès SMB, IP/port, compte, chemin relatif et droit utilisé | ne prouve pas le nombre d'octets transférés |
| Windows 4688 | processus, parent et ligne de commande si l'audit est activé | peut contenir des données sensibles ; ce n'est pas une interaction HoneyDoc sans corrélation |
| Sysmon 1/3/11/22/23/26 | processus, réseau, fichiers et DNS | Sysmon doit être installé séparément |
| Linux `auditd/execve` | exécutable, arguments, auid/uid/euid, session, TTY, PID/PPID et cwd | certains built-ins Bash ne lancent pas `execve` |
| Canarytokens | métadonnées communiquées par le fournisseur | l'IP peut être celle d'un proxy, VPN ou service de sécurité ; aucune MAC distante |

L'OS d'un User-Agent est enregistré comme déclaration de faible confiance
(`http_user_agent_claim`). L'OS de l'agent Wazuh décrit la machine surveillée,
pas nécessairement la machine distante de l'acteur.

## Chaîne de preuve Wazuh

Pour une règle JANUS 100100–100104, la même alerte canonique est enregistrée :

1. dans `wazuh_detections`, avec le verdict et le HoneyDoc correspondant ;
2. dans `raw_evidence`, avant normalisation ;
3. dans `security_signals`, après normalisation.

Les trois lignes portent la même empreinte SHA-256 de l'alerte brute. Les
événements non reconnus restent en état `normalization_pending` avec l'erreur,
au lieu d'être transformés en données inventées.

## Rétention du contexte

Wazuh Indexer demeure la source complète. SQLite conserve une copie locale
bornée pour les timelines :

```dotenv
FORENSIC_RETENTION_DAYS=3
FORENSIC_MAX_CONTEXT_SIGNALS=10000
FORENSIC_MAX_UNLINKED_RAW=1000
FORENSIC_PRUNE_INTERVAL_SECONDS=900
```

La purge ne sélectionne jamais :

- une empreinte référencée par `wazuh_detections` ;
- un signal dont le chemin correspond à un HoneyDoc enregistré.

Elle vise seulement le contexte général le plus ancien. Le statut expose
`retention_scope=supporting_context_only` et la dernière opération. Pour une
maintenance manuelle avec compactage :

```powershell
python .\scripts\maintain_telemetry.py --vacuum
```

Sauvegarder la base et arrêter l'API avant un compactage manuel.

## Installation Windows

Depuis un PowerShell administrateur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_windows_forensics.ps1" -IncludeCommandLine

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\setup_janus_audit.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_wazuh_rule.ps1" `
  -WazuhComposeRoot "C:\chemin\vers\wazuh-docker\single-node"

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_wazuh_collector.ps1" `
  -DevelopmentTrustSelfSigned
```

`-DevelopmentTrustSelfSigned` est une exception de laboratoire. En production,
utiliser la vérification TLS et une CA dont le nom correspond à l'Indexer.

## Test 4663 local

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\test_windows_forensics.ps1"
```

Le script contrôle la stratégie, la SACL, lit un HoneyDoc et exige un événement
4663 portant exactement le même chemin.

## Agent Linux

```bash
chmod +x scripts/configure_linux_auditd.sh
sudo ./scripts/configure_linux_auditd.sh --test
```

La clé `audit-wazuh-c` identifie les événements `auditd` destinés à JANUS.

## Consultation

```powershell
$headers = @{ "X-JANUS-API-Key" = $env:JANUS_ADMIN_API_KEY }
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/status" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/raw?limit=20" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/signals?limit=20" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/timeline?hostname=DESKTOP-LAB&logon_id=0xabc" -Headers $headers
```

Une timeline associe les étapes seulement si l'hôte et le Logon ID concordent.
Sans événement 4624 compatible, le point d'entrée reste vide. Un
« téléchargement » n'est affirmé que si plusieurs capteurs concordent ; sinon
l'action reste `read` ou `remote_file_access/read`.
