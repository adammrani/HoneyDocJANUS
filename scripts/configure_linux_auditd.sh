#!/usr/bin/env bash
# Configure la capture fiable des commandes externes Linux pour Wazuh/JANUS.
set -euo pipefail

AUDIT_RULE_FILE="${AUDIT_RULE_FILE:-/etc/audit/rules.d/janus-command.rules}"
OSSEC_CONF="${OSSEC_CONF:-/var/ossec/etc/ossec.conf}"
RUN_TEST=false
if [[ "${1:-}" == "--test" ]]; then
  RUN_TEST=true
fi

if [[ "${EUID}" -ne 0 ]]; then
  printf '%s\n' "Exécutez ce script avec sudo/root."
  exit 1
fi
if ! command -v auditctl >/dev/null 2>&1; then
  printf '%s\n' "auditd/auditctl est absent. Installez le paquet auditd."
  exit 1
fi
if [[ ! -f "${OSSEC_CONF}" ]]; then
  printf '%s\n' "Configuration Wazuh Agent introuvable : ${OSSEC_CONF}"
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -f "${AUDIT_RULE_FILE}" ]]; then
  cp --preserve=mode,ownership "${AUDIT_RULE_FILE}" \
    "${AUDIT_RULE_FILE}.bak-${timestamp}"
fi

rule_tmp="$(mktemp)"
conf_tmp="$(mktemp)"
trap 'rm -f "${rule_tmp}" "${conf_tmp}"' EXIT

printf '%s\n' \
  '# JANUS - commandes externes des utilisateurs humains (64 et 32 bits)' \
  '-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-c' \
  '-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-c' \
  '# JANUS - commandes des sessions root directes' \
  '-a always,exit -F arch=b64 -S execve -F auid=0 -k audit-wazuh-c' \
  '-a always,exit -F arch=b32 -S execve -F auid=0 -k audit-wazuh-c' \
  > "${rule_tmp}"
install -o root -g root -m 0640 "${rule_tmp}" "${AUDIT_RULE_FILE}"

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load
else
  auditctl -R "${AUDIT_RULE_FILE}"
fi

if ! grep -Fq '<location>/var/log/audit/audit.log</location>' "${OSSEC_CONF}"; then
  cp --preserve=mode,ownership "${OSSEC_CONF}" "${OSSEC_CONF}.bak-${timestamp}"
  awk '
    BEGIN { added = 0 }
    !added && /<\/ossec_config>/ {
      print "  <localfile>"
      print "    <log_format>audit</log_format>"
      print "    <location>/var/log/audit/audit.log</location>"
      print "  </localfile>"
      added = 1
    }
    { print }
    END { if (!added) exit 42 }
  ' "${OSSEC_CONF}" > "${conf_tmp}" || {
    printf '%s\n' "Impossible de trouver </ossec_config> dans ${OSSEC_CONF}."
    exit 1
  }
  install --reference="${OSSEC_CONF}" "${conf_tmp}" "${OSSEC_CONF}"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart wazuh-agent
fi

printf '%s\n' "Règles JANUS auditd actives :"
auditctl -l | grep -E 'audit-wazuh-c|janus-command' || true

if [[ "${RUN_TEST}" == "true" ]]; then
  /usr/bin/id >/dev/null
  printf '%s\n' "Dernières preuves auditd JANUS :"
  ausearch -k audit-wazuh-c -ts recent -i | tail -n 40
fi

printf '%s\n' \
  "Configuration terminée." \
  "Limite fiable : cd, export et les autres built-ins du shell ne lancent pas toujours execve."
