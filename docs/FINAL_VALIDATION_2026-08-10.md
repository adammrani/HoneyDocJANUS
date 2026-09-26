# JANUS final validation — 10 August 2026

## Result

The current academic MVP is operational on the validated Windows laboratory:

- FastAPI and Streamlit start independently and expose health/status views;
- Wazuh manager, indexer, and dashboard run in the Docker single-node stack;
- the Wazuh and forensic collectors run without a recorded error;
- a controlled read of HoneyDoc 26 produced event 4663 and Wazuh rule 100101;
- JANUS correlated the path to the active document and preserved raw evidence;
- the Wazuh rule ID is now a first-class dashboard/database field;
- all automated tests pass: **98 tests and 7 subtests**.

## Final code change

`src/janus_v2/registry/wazuh_detection_store.py` now stores
`wazuh_rule_id`, migrates existing databases, and backfills old rows from their
immutable raw alert when possible. `src/alerting/dashboard.py` displays that
field. `tests/test_wazuh_detection_store_v2.py` verifies the behavior.

The endurance check also found repeated `database is locked` errors during the
forensic-retention pass. The two collector stores now share a re-entrant writer
lock, use a 60-second busy timeout, and reserve the SQLite writer before
retention. A new concurrency test exercises both cursor writers. The database
was backed up, pruned, vacuumed from approximately 379 MB to 173 MB, and passed
`PRAGMA quick_check`. All 130 Wazuh detections were retained. After restart,
both collectors completed repeated polls with zero errors.

## Operational entry points

- Start: `scripts/start_janus.ps1`
- Stop: `scripts/stop_janus.ps1`
- Manual acceptance: `docs/MANUAL_TEST_GUIDE.md`
- English report source: `report/main.tex`
- Mermaid sources: `report/diagrams/`
- Screenshot checklist: `report/figures/README.md`

## Honest remaining limits

- DOCX remote activation depends on Microsoft Office external-content policy;
  the local Wazuh signal remains valid when the callback is blocked.
- Passive JSON/YAML/CSV/ENV data does not make an automatic HTTP request.
- AWS token notification requires use of the decoy keys with an AWS API.
- Wazuh cannot observe later actions on an unmanaged external computer.
- The current public Canarytokens setup reports by email; ingestion into JANUS
  needs an authenticated public HTTPS webhook.
- This single-workstation, SQLite, self-signed-certificate laboratory is not a
  production SOC deployment.
