[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$TestFile = "",
    [switch]$Repair
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $Principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw "Ouvrez PowerShell en tant qu'administrateur. La lecture d'une SACL et du journal Security exige cette autorisation."
    }
}

function Test-IsDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$AllowedRoot
    )

    $RootWithSeparator = $AllowedRoot.TrimEnd("\") + "\"
    return $Candidate.StartsWith(
        $RootWithSeparator,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Convert-EventDataToMap {
    param([Parameter(Mandatory = $true)]$Event)

    [xml]$Xml = $Event.ToXml()
    $Result = @{}
    foreach ($Data in $Xml.Event.EventData.Data) {
        $Name = [string]$Data.Name
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $Result[$Name] = [string]$Data.'#text'
        }
    }
    return $Result
}

Assert-Administrator

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Join-Path $PSScriptRoot ".."
}
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$SharedRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $ProjectRoot "data\shared")
).TrimEnd("\")

if (-not (Test-Path -LiteralPath $SharedRoot -PathType Container)) {
    throw "Dossier surveille introuvable : $SharedRoot"
}

if ($Repair) {
    Write-Host "Reparation de la strategie d'audit et de la SACL..."
    & (Join-Path $PSScriptRoot "configure_windows_forensics.ps1") `
        -IncludeCommandLine
    & (Join-Path $PSScriptRoot "setup_janus_audit.ps1") `
        -Path $SharedRoot
}

$AuditSubcategories = [ordered]@{
    "Logon / 4624" = "{0CCE9215-69AE-11D9-BED3-505054503030}"
    "File System / 4663" = "{0CCE921D-69AE-11D9-BED3-505054503030}"
    "Detailed File Share / 5145" = "{0CCE9244-69AE-11D9-BED3-505054503030}"
    "Process Creation / 4688" = "{0CCE922B-69AE-11D9-BED3-505054503030}"
}

Write-Host "Strategie d'audit Windows :"
foreach ($Entry in $AuditSubcategories.GetEnumerator()) {
    Write-Host "--- $($Entry.Key)"
    & auditpol.exe /get "/subcategory:$($Entry.Value)" /r
    if ($LASTEXITCODE -ne 0) {
        throw "Impossible de lire la sous-categorie d'audit $($Entry.Key)."
    }
}

$EveryoneSid = "S-1-1-0"
$Sacls = (Get-Acl -LiteralPath $SharedRoot -Audit).GetAuditRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
) | Where-Object {
    $_.IdentityReference.Value -eq $EveryoneSid
}

if ($null -eq $Sacls -or @($Sacls).Count -eq 0) {
    throw "Aucune SACL JANUS pour Everyone n'est presente sur $SharedRoot. Relancez avec -Repair."
}

Write-Host "SACL active sur $SharedRoot :"
$Sacls | Select-Object `
    IdentityReference,
    FileSystemRights,
    AuditFlags,
    InheritanceFlags,
    PropagationFlags,
    IsInherited | Format-Table -AutoSize

if ([string]::IsNullOrWhiteSpace($TestFile)) {
    $Candidate = Get-ChildItem -LiteralPath $SharedRoot -File -Recurse |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $Candidate) {
        throw "Aucun honeydocument n'existe dans $SharedRoot. Generez-en un avant le test."
    }
    $TestFile = $Candidate.FullName
}

$TestFile = [System.IO.Path]::GetFullPath($TestFile)
if (-not (Test-IsDescendantPath -Candidate $TestFile -AllowedRoot $SharedRoot)) {
    throw "Fichier refuse : le test est limite a data\shared."
}
if (-not (Test-Path -LiteralPath $TestFile -PathType Leaf)) {
    throw "Fichier de test introuvable : $TestFile"
}

$StartedAt = Get-Date
$BytesRead = [System.IO.File]::ReadAllBytes($TestFile).Length
Write-Host "Lecture controlee : $BytesRead octets dans $TestFile"
Start-Sleep -Seconds 2

$SearchStart = $StartedAt.AddSeconds(-2)
$Recent4663 = Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4663
    StartTime = $SearchStart
} -ErrorAction SilentlyContinue

$Matches = foreach ($Event in $Recent4663) {
    $Data = Convert-EventDataToMap -Event $Event
    if ([string]::Equals(
        [string]$Data["ObjectName"],
        $TestFile,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        [pscustomobject]@{
            TimeCreated = $Event.TimeCreated
            EventId = $Event.Id
            ObjectName = $Data["ObjectName"]
            ProcessName = $Data["ProcessName"]
            SubjectUserName = $Data["SubjectUserName"]
            SubjectLogonId = $Data["SubjectLogonId"]
            AccessMask = $Data["AccessMask"]
            AccessList = $Data["AccessList"]
            RecordId = $Event.RecordId
        }
    }
}

if ($null -eq $Matches -or @($Matches).Count -eq 0) {
    throw "TEST ECHOUE : Windows n'a emis aucun 4663 pour cette lecture. Relancez avec -Repair puis recommencez."
}

Write-Host "TEST REUSSI : Windows a emis 4663."
$Matches | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

$WazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($null -eq $WazuhService) {
    Write-Warning "Service WazuhSvc introuvable : le 4663 local ne pourra pas etre transmis par cet agent."
}
elseif ($WazuhService.Status -ne "Running") {
    Write-Warning "WazuhSvc est $($WazuhService.Status). Demarrez le service avant de verifier le Dashboard."
}
else {
    Write-Host "WazuhSvc est actif. Cherchez ensuite rule.id:100100 dans le Dashboard Wazuh."
}
