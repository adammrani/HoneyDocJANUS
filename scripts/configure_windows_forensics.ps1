[CmdletBinding()]
param(
    [string]$BackupDirectory = "",
    [string]$WazuhAgentConfig = "C:\Program Files (x86)\ossec-agent\ossec.conf",
    [switch]$IncludeCommandLine
)

$ErrorActionPreference = "Stop"
$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ouvrez PowerShell en tant qu'administrateur."
}

if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $PSScriptRoot "..\backups\windows-audit"
}
$BackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$AuditBackup = Join-Path $BackupDirectory "audit-policy-$Timestamp.csv"

& auditpol.exe /backup "/file:$AuditBackup" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "La sauvegarde de la stratégie d'audit Windows a échoué."
}

$Subcategories = [ordered]@{
    "Logon / 4624" = "{0CCE9215-69AE-11D9-BED3-505054503030}"
    "File System / 4663" = "{0CCE921D-69AE-11D9-BED3-505054503030}"
    "Detailed File Share / 5145" = "{0CCE9244-69AE-11D9-BED3-505054503030}"
    "Process Creation / 4688" = "{0CCE922B-69AE-11D9-BED3-505054503030}"
}

foreach ($Entry in $Subcategories.GetEnumerator()) {
    & auditpol.exe /set "/subcategory:$($Entry.Value)" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Impossible d'activer $($Entry.Key). Restauration possible avec $AuditBackup"
    }
    Write-Output "Activé : $($Entry.Key)"
}

if ($IncludeCommandLine) {
    $AuditRegistry = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $AuditRegistry -Force | Out-Null
    New-ItemProperty `
        -Path $AuditRegistry `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null
    Write-Warning "Les lignes de commande 4688 peuvent contenir des secrets. Restreignez l'accès à Wazuh."
}

function Add-WazuhEventChannel([string]$Location) {
    if (-not (Test-Path -LiteralPath $WazuhAgentConfig -PathType Leaf)) {
        Write-Warning "Agent Wazuh introuvable : $WazuhAgentConfig"
        return $false
    }
    $Content = [System.IO.File]::ReadAllText($WazuhAgentConfig)
    $Marker = "<location>$Location</location>"
    if ($Content.Contains($Marker)) {
        Write-Host "Canal Wazuh déjà présent : $Location"
        return $false
    }
    if ($Content -notmatch "(?s)</ossec_config>\s*$") {
        throw "Balise finale </ossec_config> absente : $WazuhAgentConfig"
    }

    $ConfigBackup = "$WazuhAgentConfig.bak-$Timestamp"
    Copy-Item -LiteralPath $WazuhAgentConfig -Destination $ConfigBackup -Force
    $Block = @"
  <localfile>
    <location>$Location</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
    $Updated = [regex]::Replace(
        $Content,
        "(?s)</ossec_config>\s*$",
        "$Block`r`n</ossec_config>`r`n"
    )
    [System.IO.File]::WriteAllText(
        $WazuhAgentConfig,
        $Updated,
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "Canal Wazuh ajouté : $Location (sauvegarde $ConfigBackup)"
    return $true
}

$WazuhChanged = Add-WazuhEventChannel "Security"
$SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue
if ($null -ne $SysmonService) {
    $WazuhChanged = (Add-WazuhEventChannel "Microsoft-Windows-Sysmon/Operational") -or $WazuhChanged
}
else {
    Write-Output "Sysmon non installé : les événements Sysmon resteront facultatifs."
}
if ($WazuhChanged) {
    $WazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($null -ne $WazuhService) {
        Restart-Service -Name "WazuhSvc"
        Write-Output "Agent Wazuh redémarré."
    }
}

Write-Output "Sauvegarde de la stratégie précédente : $AuditBackup"
Write-Output "Vérification :"
foreach ($Entry in $Subcategories.GetEnumerator()) {
    & auditpol.exe /get "/subcategory:$($Entry.Value)" /r
}
Write-Output "La SACL du dossier data\shared reste nécessaire pour produire 4663."
