[CmdletBinding()]
param(
    [switch]$IncludeCommandLine
)

$ErrorActionPreference = "Stop"
$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ouvrez PowerShell en tant qu'administrateur."
}

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$BackupDirectory = Join-Path $ProjectRoot "data\windows-audit-backups"
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
        throw "Impossible d'activer $($Entry.Key). Restauration : $AuditBackup"
    }
    Write-Output "Activé : $($Entry.Key)"
}

if ($IncludeCommandLine) {
    $AuditRegistry = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $AuditRegistry -Force | Out-Null
    New-ItemProperty -Path $AuditRegistry -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Warning "Les lignes de commande 4688 peuvent contenir des secrets. Limitez leur accès."
}

Write-Output "Stratégie précédente sauvegardée : $AuditBackup"
Write-Output "Exécutez ensuite scripts\setup_janus_audit.ps1 pour la SACL du dossier JANUS."

