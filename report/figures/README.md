# Screenshot plan for the JANUS report

Use a consistent browser zoom, crop unused desktop areas, and keep the text
readable on an A4 page. Never capture `.env`, `X-JANUS-API-Key`, full AWS token
credentials, Canarytokens management URLs, or unredacted personal email data.

## Already preserved

1. `evidence/wazuh-rule-100101.png` — Wazuh rule 100101 and description.
2. `evidence/wazuh-4663-fields.png` — object path, process, access mask, and user.
3. `evidence/windows-sacl-4663-test.png` — inherited SACL and controlled 4663 test.
4. `evidence/janus-telemetry-status.png` — collector status and cursor.

## Essential new screenshots

1. `dashboard-alerts.png` — JANUS Alerts page with the local Wazuh table and the
   separate Canarytokens section. Use a recent controlled event.
2. `dashboard-generate-json.png` — Generate page after selecting
   `technical_config` and `json`, before submitting.
3. `dashboard-active-honeydocs.png` — active HoneyDocs list showing several
   formats and only safe metadata.
4. `generated-docx.png` — the generated DOCX opened normally, showing plausible
   business content and no macro prompt.
5. `generated-xlsx.png` — the accounting workbook opened without an Excel repair
   dialog; include a useful table, not the whole desktop.
6. `generated-json.png` — a generated `.json` in an editor, with valid syntax and
   the `.json` suffix visible.
7. `canary-office-email-redacted.png` — provider email showing token type,
   timestamp, channel, User-Agent, and redacted public IP.
8. `tests-98-passed.png` — terminal result `98 passed ... 7 subtests passed`.
9. `wazuh-containers-healthy.png` — the three Wazuh services shown as running.

## Optional screenshots

1. `aws-token-policy.png` — JANUS page describing that opening ENV does not
   activate the token and that AWS API use is required. Do not show the key pair.
2. `wazuh-modify-delete.png` — rules 100102 and 100103 after controlled edits.
3. `api-health.png` — `/health`, `/wazuh/status`, and `/telemetry/status`, with no
   API key visible.
4. `docker-and-janus-layout.png` — File Explorer view of the source, scripts,
   report, and monitored `data/shared` directory.

## Captions should state evidence, not interpretation

Prefer: “Event 4663 reports a read access by PowerShell on HoneyDoc 26.”

Avoid: “The attacker downloaded the document.” A single read event does not
prove a remote download.
