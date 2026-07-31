# Télémétrie forensique JANUS v2

JANUS sépare les **observations directes** des **inférences**. Chaque événement
est conservé dans SQLite (`security_signals`) avec son alerte Wazuh brute.

## Sources activées

| Source | Preuve fiable | Limite |
|---|---|---|
| Windows 4663 + SACL | droit de lecture, écriture ou suppression réellement utilisé sur le fichier | une lecture n'est pas la preuve que tout le contenu a été affiché |
| Windows 4624 | compte, Logon ID, type de connexion, IP/port lorsque Windows les fournit | une connexion locale ne fournit pas toujours d'IP distante |
| Windows 5145 | accès SMB, IP/port, compte, chemin relatif et droit utilisé | ne donne pas à lui seul le nombre d'octets transférés |
| Windows 4688 | processus créé, parent et ligne de commande si la stratégie correspondante est active | la ligne de commande peut contenir des secrets |
| Sysmon 1/3/11/22/23/26 | processus, réseau, création/suppression de fichier et DNS | Sysmon doit être installé et configuré séparément |
| Linux auditd execve | exécutable, arguments, auid/uid/euid, session, TTY, PID/PPID et cwd | `cd`, `export` et autres built-ins Bash ne lancent pas toujours `execve` |
| Canarytoken | IP publique de sortie, date, User-Agent et métadonnées du fournisseur | l'IP peut être celle d'un proxy/VPN; MAC distante indisponible sur Internet |

## Installation Windows

Depuis un PowerShell administrateur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_windows_forensics.ps1" `
  -IncludeCommandLine

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\setup_janus_audit.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_wazuh_rule.ps1" `
  -WazuhComposeRoot "C:\chemin\vers\wazuh-docker\single-node"

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\configure_wazuh_collector.ps1" `
  -DevelopmentTrustSelfSigned
```

`configure_windows_forensics.ps1` sauvegarde la stratégie d'audit avant toute
modification. `setup_janus_audit.ps1` applique la SACL héritée uniquement au
dossier `data/shared`.

## Installation sur un agent Linux Wazuh

Copier le dépôt sur la machine surveillée, puis :

```bash
chmod +x scripts/configure_linux_auditd.sh
sudo ./scripts/configure_linux_auditd.sh --test
```

Le script crée `/etc/audit/rules.d/janus-command.rules`, ajoute le journal
auditd à l'agent Wazuh si nécessaire et redémarre l'agent. La clé stable
`audit-wazuh-c` permet au manager et à JANUS d'identifier ces événements.

## Diagnostic local de l'evenement 4663

Depuis un PowerShell administrateur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\test_windows_forensics.ps1"
```

Le script verifie la strategie d'audit, lit la SACL de `data/shared`, effectue
une lecture controlee du honeydocument le plus recent et exige un evenement
local 4663 portant exactement le meme chemin. Avec `-Repair`, il reactive
d'abord la strategie d'audit et la SACL. Cela permet de separer un probleme
Windows d'un probleme de transport ou de regle Wazuh.

## Validation API

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/status"
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/signals?limit=20"
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/signals?platform=linux&kind=command_execution"
Invoke-RestMethod "http://127.0.0.1:8000/telemetry/timeline?hostname=DESKTOP-LAB&logon_id=0xabc"
```

La timeline n'associe les étapes que si **l'hôte et l'identifiant de session**
correspondent. Elle expose le premier événement `4624` comme point d'entrée
observé; si cet événement manque, `entry_point` reste vide.

Le collecteur est désactivé par défaut pour éviter de stocker des lignes de
commande sans décision explicite. Il est activé par
`configure_wazuh_collector.ps1`; `.env` reste hors Git.

Les types de session techniques `0` (système), `4` (batch), `5` (service) et
`7` (déverrouillage) ne sont pas ingérés comme points d'entrée. JANUS conserve
par défaut `2,3,8,9,10,11,12,13`, configurable par `FORENSIC_LOGON_TYPES`.

## Données qu'il ne faut pas inventer

- Une adresse MAC n'est disponible que sur le même segment réseau ou par une
  source fiable comme DHCP, NAC, ARP ou EDR. Elle ne traverse pas Internet.
- L'OS déduit d'un User-Agent est une estimation. L'OS de l'agent Wazuh est en
  revanche une donnée d'inventaire fiable.
- JANUS stocke donc `os_evidence_source=http_user_agent_claim` et
  `os_confidence=low`; une chaîne User-Agent ne devient jamais une preuve forte.
- Une géolocalisation IP est approximative et doit conserver le fournisseur et
  la date d'enrichissement.
- Un « téléchargement » est qualifié comme tel seulement si plusieurs preuves
  concordent (SMB 5145 en lecture, connexion réseau/processus, éventuellement
  télémétrie serveur). Sinon JANUS affiche `remote_file_access/read`.
