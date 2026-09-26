[CmdletBinding()]
param(
    [switch]$StopWazuh,
    [string]$WazuhComposeRoot = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$PidPath = Join-Path $ProjectRoot "data\runtime\janus-processes.json"

function Stop-RecordedProcess {
    param(
        [int]$ProcessId,
        [string]$ExpectedStartTime,
        [string]$Label
    )

    $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $Process) {
        Write-Output "$Label est déjà arrêté."
        return
    }
    $ActualStartTime = $Process.StartTime.ToUniversalTime().ToString("o")
    if ($ActualStartTime -ne $ExpectedStartTime) {
        throw "PID $ProcessId réutilisé : arrêt de $Label refusé."
    }
    Stop-Process -Id $ProcessId -Force
    Write-Output "$Label arrêté (PID $ProcessId)."
}

if (Test-Path -LiteralPath $PidPath) {
    $State = Get-Content -Raw -LiteralPath $PidPath | ConvertFrom-Json
    Stop-RecordedProcess -ProcessId ([int]$State.api_pid) `
        -ExpectedStartTime ([string]$State.api_started_at) -Label "API JANUS"
    Stop-RecordedProcess -ProcessId ([int]$State.dashboard_pid) `
        -ExpectedStartTime ([string]$State.dashboard_started_at) `
        -Label "Dashboard JANUS"
    Remove-Item -LiteralPath $PidPath -Force
}
else {
    Write-Output "Aucun fichier PID JANUS : aucun processus arrêté."
}

if ($StopWazuh) {
    if ([string]::IsNullOrWhiteSpace($WazuhComposeRoot)) {
        throw "-WazuhComposeRoot est obligatoire avec -StopWazuh."
    }
    Push-Location ([System.IO.Path]::GetFullPath($WazuhComposeRoot))
    try {
        & docker compose stop
        if ($LASTEXITCODE -ne 0) {
            throw "L'arrêt de Wazuh a échoué."
        }
    }
    finally {
        Pop-Location
    }
}

