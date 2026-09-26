# JANUS Manual Acceptance Test

This guide validates only the supported core: AI-assisted HoneyDoc generation,
deployment in `data/shared`, local Wazuh detection, official Canarytokens, and
the JANUS dashboard. Experimental fake SSH/HTTP services are intentionally out
of scope.

## 1. Prerequisites

- Windows 10/11 with the Wazuh agent installed and running.
- Docker Desktop and the Wazuh single-node stack.
- Python 3.11 or newer with the project dependencies installed.
- Microsoft Word and Excel for the Office tests.
- An email address configured in `.env` for Canarytokens alerts.

Never publish `.env`, `data/honeydocs.db`, generated tokens, live AWS decoy
credentials, or unredacted alert emails.

## 2. One-time initialization

Open PowerShell in `C:\Users\Asus\Desktop\HoneyDocJANUS`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\bootstrap_janus.ps1 -InstallDependencies `
  -PythonExe C:\Python314\python.exe
```

Then open **PowerShell as Administrator** and apply the Windows audit setup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\configure_windows_forensics.ps1 -IncludeCommandLine

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\setup_janus_audit.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\configure_wazuh_rule.ps1 `
  -WazuhComposeRoot "C:\Users\Asus\Desktop\wazuh-docker\single-node"
```

Run these commands again only after changing the monitored path or Wazuh rules.

## 3. Start the platform

Start Docker Desktop. Then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\start_janus.ps1 `
  -PythonExe C:\Python314\python.exe `
  -WazuhComposeRoot "C:\Users\Asus\Desktop\wazuh-docker\single-node"
```

Expected URLs:

- API health: <http://127.0.0.1:8000/health>
- API documentation: <http://127.0.0.1:8000/docs>
- JANUS dashboard: <http://127.0.0.1:8501>
- Wazuh dashboard: <https://localhost>

The API log must contain:

- `Automatic Wazuh collection started`;
- `Windows/Linux forensic telemetry collection started`;
- no `last_error` message.

## 4. Automated verification

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\verify_project.ps1 `
  -PythonExe C:\Python314\python.exe -SkipDocker
```

Acceptance criterion: all tests pass. The current reference result is **98
tests and 7 subtests**. The Starlette/httpx deprecation warning is non-blocking.

## 5. Check Wazuh and Canarytokens status

Load the administration key without printing it:

```powershell
$line = Get-Content .env | Where-Object { $_ -match '^JANUS_ADMIN_API_KEY=' }
$key = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
$headers = @{ 'X-JANUS-API-Key' = $key }

Invoke-RestMethod http://127.0.0.1:8000/wazuh/status -Headers $headers
Invoke-RestMethod http://127.0.0.1:8000/telemetry/status -Headers $headers
Invoke-RestMethod http://127.0.0.1:8000/canary/status -Headers $headers
```

Expected: Wazuh and telemetry are `enabled=true`, `running=true`, with an empty
`last_error`; Canarytokens is configured. `webhook_enabled=false` is expected
when the public service sends alerts only by email.

## 6. Generate four representative HoneyDocs

Open <http://127.0.0.1:8501>, choose **Generate**, and create:

1. `financial_report -> docx`;
2. `financial_report -> xlsx`;
3. `technical_config -> json`;
4. `cloud_credentials -> env`.

Confirm the exact suffix of every generated file in `data/shared`. JSON must
produce `.json`, never `.docx`. Do not reuse old DOCX files created before the
beacon correction.

## 7. DOCX test

1. Double-click the new DOCX in File Explorer.
2. Keep Word open for 20 to 45 seconds.
3. In JANUS, open **Alerts** and look for the filename.
4. In Wazuh Threat Hunting, filter with:

```text
rule.id:(100101 OR 100104)
```

Expected local evidence: event 4663, the file path, account, `WINWORD.EXE`,
action `read`, and rule 100101 or 100104. A Canarytokens email is expected only
if Word and the network policy allow external content.

## 8. XLSX test

1. Double-click the new XLSX in Excel.
2. Wait up to one minute for the local signal.
3. Check the JANUS/Wazuh dashboards and the Canarytokens email.

Expected: a Wazuh read/open signal and, when external content is allowed, a
Canarytokens email containing the public source IP and the Office user-agent.

## 9. JSON test

1. Open the JSON with Notepad or VS Code.
2. Verify that JANUS reports the read after the Wazuh propagation delay.
3. Confirm that no automatic Canarytokens email is received.

This is correct: a passive JSON file cannot initiate a network request by
itself. Its web breadcrumb alerts only when the included URL is used.

## 10. AWS credential token test

Opening the ENV file must create a local Wazuh signal but no email. To validate
the remote layer, use **only the generated decoy credentials** with an AWS API
client in a controlled test. Never use real credentials. Canarytokens documents
that the provider alert can take 2 to 30 minutes because it traverses AWS
logging infrastructure.

Expected: the AWS request fails to grant access, while the provider sends an
alert. Remove the credentials from the shell environment immediately after the
test.

## 11. Modification, move, and deletion

Work on a disposable generated test document:

- edit and save it: expect rule 100102 / action `modify`;
- move it out of `data/shared`: the source-side operation can appear as a delete
  or rename sequence, depending on Windows events;
- delete it: expect rule 100103 / action `delete`.

A single 4663 read does **not** prove that a file was viewed, copied, or remotely
downloaded. JANUS must preserve `read` unless corroborating process, SMB, logon,
or network evidence exists.

## 12. Stop the platform

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\stop_janus.ps1
```

Wazuh remains running by default. To stop it as well, add `-StopWazuh` and its
compose root.

## Acceptance matrix

| Test | Wazuh | Remote Canarytokens |
|---|---|---|
| DOCX opened in Word | Expected | Conditional on Office/network policy |
| XLSX opened in Excel | Expected | Conditional on Office/network policy |
| JSON opened | Expected | Not automatic |
| AWS ENV opened | Expected | Not expected |
| AWS decoy keys used with AWS API | Not necessarily | Expected, possibly delayed |
| File modified/deleted locally | Expected | Not related |
