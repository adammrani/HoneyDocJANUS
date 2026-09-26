# Canarytokens — configuration JANUS

JANUS utilise l'API officielle pour créer un token adapté à l'artefact :
`ms_word`, `ms_excel`, `web` ou `aws_keys`. Les alertes par e-mail fonctionnent
sans exposer l'API JANUS sur Internet.

## Configuration

Dans `.env` :

```dotenv
CANARYTOKEN_SERVER=https://canarytokens.org
CANARYTOKEN_API_PATH=/d3aece8093b71007b5ccfedad91ebb11
CANARYTOKEN_EMAIL=votre-adresse@example.net
CANARYTOKEN_TIMEOUT_SECONDS=10
CANARYTOKEN_FAIL_CLOSED=true
CANARYTOKEN_WEBHOOK_ENABLED=false
CALLBACK_BASE_URL=http://localhost:8000
```

Le chemin d'API est celui fourni par le service lors de la création d'un
factory token. Il doit rester dans `.env`, hors Git.

Avec une API locale, conserver `CANARYTOKEN_WEBHOOK_ENABLED=false` : le service
public ne peut pas joindre `localhost`. Les e-mails restent fonctionnels. Un
webhook exige une URL HTTPS publique correctement sécurisée.

`CANARYTOKEN_FAIL_CLOSED=true` bloque la génération si l'e-mail, l'API ou le
réseau manque. Le mode local de développement n'est autorisé que si cette valeur
est explicitement mise à `false`.

## Politique par artefact

| Artefact | Type API | Déclencheur |
|---|---|---|
| DOCX | `ms_word` | chargement du contenu externe par Word |
| XLSX | `ms_excel` | chargement du contenu externe par Excel |
| Formats structurés non cloud | `web` | utilisation volontaire du lien |
| `cloud_credentials` ENV/YAML/JSON/ZIP | `aws_keys` | utilisation des clés contre une API AWS |

Une ouverture Office peut être bloquée par le mode protégé ou une stratégie
réseau. Une simple lecture des fichiers AWS ne déclenche pas l'alerte distante.
Dans les deux cas, Wazuh détecte indépendamment l'accès sur la machine
surveillée.

## Validation de configuration

Après redémarrage de l'API :

```powershell
$headers = @{ "X-JANUS-API-Key" = $env:JANUS_ADMIN_API_KEY }
Invoke-RestMethod http://127.0.0.1:8000/canary/status -Headers $headers
```

Pour tester uniquement un token Web :

```powershell
$test = Invoke-RestMethod -Method Post `
  http://127.0.0.1:8000/canary/test-token -Headers $headers
$test
Start-Process $test.token_url
```

La création ne déclenche rien. L'ouverture volontaire de `token_url` déclenche
l'e-mail.

Pour un HoneyDoc AWS, générer `cloud_credentials/env` puis vérifier seulement
que la réponse annonce `token_type=aws_keys` et
`token_activation=aws_api_usage_email`. Ne pas utiliser les clés pendant un test
de génération : leur utilisation produit une vraie alerte Canarytokens.

## Cycle de vie

La base conserve le token de gestion nécessaire à la révocation. Lors d'une
rotation activée, JANUS crée d'abord le remplaçant, révoque ensuite le token
officiel expiré, puis retire l'ancien fichier. Les routes locales `/ping` et
`/ci1` rejettent les tokens dont le HoneyDoc est inactif ou révoqué.
