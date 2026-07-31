[CmdletBinding()]
param(
    [string]$AgentIds = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$EnvPath = Join-Path $ProjectRoot ".env"
if (-not (Test-Path -LiteralPath $EnvPath -PathType Leaf)) {
    throw ".env introuvable : configurez d'abord le collecteur Wazuh."
}

$BackupPath = "$EnvPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $EnvPath -Destination $BackupPath -Force

function Set-DotEnvValue(
    [System.Collections.Generic.List[string]]$Lines,
    [string]$Name,
    [string]$Value
) {
    $Replacement = "$Name=$Value"
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        if ($Lines[$Index] -match "^\s*$([regex]::Escape($Name))\s*=") {
            $Lines[$Index] = $Replacement
            return
        }
    }
    $Lines.Add($Replacement)
}

$Lines = [System.Collections.Generic.List[string]]::new()
Get-Content -LiteralPath $EnvPath | ForEach-Object { $Lines.Add($_) }
Set-DotEnvValue $Lines "FORENSIC_TELEMETRY_ENABLED" "true"
Set-DotEnvValue $Lines "FORENSIC_WINDOWS_EVENT_IDS" (
    '"4624,4663,4688,5145,1,3,11,22,23,26"'
)
Set-DotEnvValue $Lines "FORENSIC_AUDIT_KEYS" (
    '"audit-wazuh-c,janus-command"'
)
Set-DotEnvValue $Lines "FORENSIC_AGENT_IDS" ('"' + $AgentIds + '"')
Set-DotEnvValue $Lines "FORENSIC_LOGON_TYPES" '"2,3,8,9,10,11,12,13"'
Set-DotEnvValue $Lines "WAZUH_ADDITIONAL_RULE_IDS" (
    '"100101,100102,100103,100104"'
)

[System.IO.File]::WriteAllLines(
    $EnvPath,
    $Lines,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Télémétrie forensique activée dans $EnvPath"
Write-Output "Sauvegarde : $BackupPath"
Write-Output "Identifiants et mot de passe Wazuh inchangés."
Write-Output "Agents filtrés : $(if ($AgentIds) { $AgentIds } else { 'tous' })"
