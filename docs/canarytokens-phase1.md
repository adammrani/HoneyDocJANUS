# Canarytokens — phase 1

Cette phase relie JANUS à l'API actuelle de Canarytokens pour créer des
URL-tokens et recevoir les alertes par e-mail.

## Configuration locale

Dans `.env` :

```dotenv
CANARYTOKEN_SERVER=https://canarytokens.org
CANARYTOKEN_API_PATH=/d3aece8093b71007b5ccfedad91ebb11
CANARYTOKEN_EMAIL=votre-adresse@example.net
CANARYTOKEN_TIMEOUT_SECONDS=10
CANARYTOKEN_WEBHOOK_ENABLED=false
CALLBACK_BASE_URL=http://localhost:8000
```

`CANARYTOKEN_WEBHOOK_ENABLED` doit rester à `false` avec une API locale.
Le service public ne peut pas appeler `localhost`. L'e-mail reste entièrement
fonctionnel. Le webhook pourra être activé plus tard avec une URL HTTPS publique.

## Validation

Après redémarrage de l'API :

```powershell
$headers = @{ "X-JANUS-API-Key" = $env:JANUS_ADMIN_API_KEY }
Invoke-RestMethod http://127.0.0.1:8000/canary/status -Headers $headers
$test = Invoke-RestMethod -Method Post `
  http://127.0.0.1:8000/canary/test-token -Headers $headers
$test
Start-Process $test.token_url
```

La création du test ne déclenche aucune alerte. Seule l'ouverture volontaire de
`token_url` déclenche l'e-mail.

## État des formats

- DOCX : URL-token distant généré quand le fournisseur est configuré, avec
  repli local en cas d'indisponibilité.
- XLSX : token `msexcel` et image externe OOXML intégrés, avec surveillance
  locale Wazuh en seconde couche.
- CSV/JSON/YAML/ENV/ZIP : URL breadcrumb et faux endpoint ; aucun callback
  automatique n'est promis à la simple ouverture.
- Aucun format n'utilise de macro.
