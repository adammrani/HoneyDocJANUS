[CmdletBinding()]
param(
    [string]$WazuhComposeRoot = "",
    [switch]$RenderOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..")
)
$DeployRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $ProjectRoot "data\shared")
).TrimEnd("\")
$OutputDirectory = Join-Path $ProjectRoot "data\wazuh"
$OutputPath = Join-Path $OutputDirectory "janus_rules.xml"

New-Item -ItemType Directory -Path $DeployRoot -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# Wazuh conserve les séparateurs Windows doublés dans le champ décodé.
# On double donc à nouveau les séparateurs échappés produits par Regex.Escape.
$EscapedPath = [regex]::Escape($DeployRoot).Replace('\\', '\\\\')
$Pattern = "(?i)^$EscapedPath\\\\"
$XmlPattern = [System.Security.SecurityElement]::Escape($Pattern)
$RuleXml = @"
<group name="janus,">
  <rule id="100100" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4663$</field>
    <field name="win.eventdata.objectName" type="pcre2">$XmlPattern</field>
    <description>JANUS: Access to an audited decoy file.</description>
    <options>no_full_log</options>
    <group>windows,windows_security,janus_file_access,</group>
  </rule>

  <rule id="100101" level="8">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.accessList" type="pcre2">(?i)%%4416</field>
    <description>JANUS READ/OPEN candidate: audited decoy file read.</description>
    <group>windows,janus_read,</group>
  </rule>

  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.accessList" type="pcre2">(?i)(%%4417|%%4418)</field>
    <description>JANUS MODIFY: audited decoy file written or appended.</description>
    <group>windows,janus_modify,</group>
  </rule>

  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.accessList" type="pcre2">(?i)%%1537</field>
    <description>JANUS DELETE: audited decoy file deletion right used.</description>
    <group>windows,janus_delete,</group>
  </rule>

  <rule id="100104" level="9">
    <if_sid>100101</if_sid>
    <field name="win.eventdata.processName" type="pcre2">(?i)\\(WINWORD|EXCEL|POWERPNT|ACRORD32)\.EXE$</field>
    <description>JANUS OPEN candidate: decoy read by an Office/PDF application.</description>
    <group>windows,janus_open_candidate,</group>
  </rule>

  <rule id="100110" level="3">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.logonType" type="pcre2">^(2|3|8|9|10|11|12|13)$</field>
    <description>JANUS WINDOWS LOGON: successful session entry evidence.</description>
    <group>windows,authentication_success,janus_entry_point,</group>
  </rule>

  <rule id="100111" level="5">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^5145$</field>
    <description>JANUS REMOTE FILE ACCESS: detailed SMB share access.</description>
    <group>windows,network_share,janus_remote_file,</group>
  </rule>

  <rule id="100112" level="5">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4688$</field>
    <field name="win.eventdata.newProcessName" type="pcre2">(?i)\\(cmd|powershell|pwsh|curl|wget|certutil|bitsadmin|python|bash|wsl|ssh|scp|sftp|robocopy|winword|excel|powerpnt|acrord32)\.exe$</field>
    <description>JANUS WINDOWS COMMAND: relevant process creation observed.</description>
    <group>windows,process_creation,janus_command,</group>
  </rule>

  <rule id="100130" level="8">
    <if_sid>80792</if_sid>
    <field name="audit.key" type="pcre2">^(audit-wazuh-c|janus-command)$</field>
    <description>JANUS LINUX COMMAND: an audited execve command was executed.</description>
    <group>linux,auditd,janus_command,</group>
  </rule>
</group>
"@

[System.IO.File]::WriteAllText(
    $OutputPath,
    $RuleXml,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Règle générée : $OutputPath"
Write-Output "Dossier surveillé : $DeployRoot"
Write-Output "Expression Wazuh : $Pattern"

if ($RenderOnly) {
    return
}

if ([string]::IsNullOrWhiteSpace($WazuhComposeRoot)) {
    throw "Indique -WazuhComposeRoot ou utilise -RenderOnly."
}

$ComposeRoot = [System.IO.Path]::GetFullPath($WazuhComposeRoot)
if (-not (Test-Path -LiteralPath (Join-Path $ComposeRoot "docker-compose.yml"))) {
    throw "Stack Wazuh introuvable : $ComposeRoot"
}

Push-Location $ComposeRoot
try {
    $ManagerId = (& docker compose ps -q wazuh.manager).Trim()
    if ([string]::IsNullOrWhiteSpace($ManagerId)) {
        throw "Le conteneur wazuh.manager n'est pas actif."
    }

    $BackupPath = Join-Path $OutputDirectory "janus_rules.previous.xml"
    & docker cp "${ManagerId}:/var/ossec/etc/rules/janus_rules.xml" $BackupPath
    $HasBackup = $LASTEXITCODE -eq 0

    & docker cp $OutputPath "${ManagerId}:/var/ossec/etc/rules/janus_rules.xml"
    if ($LASTEXITCODE -ne 0) {
        throw "Impossible de copier la règle dans le manager Wazuh."
    }

    & docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-analysisd -t
    if ($LASTEXITCODE -ne 0) {
        if ($HasBackup) {
            & docker cp $BackupPath "${ManagerId}:/var/ossec/etc/rules/janus_rules.xml"
        }
        throw "La validation Wazuh a échoué. Ancienne règle restaurée."
    }

    & docker compose restart wazuh.manager
    if ($LASTEXITCODE -ne 0) {
        throw "La règle est valide, mais le manager n'a pas redémarré."
    }
}
finally {
    Pop-Location
}

Write-Output "Règle JANUS installée dans Wazuh."
