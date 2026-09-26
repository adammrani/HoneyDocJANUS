[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [string]$WazuhComposeRoot = "",
    [int]$StartupTimeoutSeconds = 45
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$RuntimeRoot = Join-Path $ProjectRoot "data\runtime"
$PidPath = Join-Path $RuntimeRoot "janus-processes.json"

function Get-ListeningPid {
    param([int]$Port)

    foreach ($line in (netstat -ano -p tcp)) {
        if ($line -match "^\s*TCP\s+\S+:$Port\s+\S+\s+LISTENING\s+(\d+)\s*$") {
            return [int]$Matches[1]
        }
    }
    return $null
}

function Wait-Http {
    param([string]$Uri, [int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "Service indisponible après $TimeoutSeconds secondes : $Uri"
}

if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot ".env"))) {
    throw "Fichier .env absent. Lancez d'abord scripts\bootstrap_janus.ps1."
}

$PythonPath = (Get-Command $PythonExe -ErrorAction Stop).Source
foreach ($port in 8000, 8501) {
    $listener = Get-ListeningPid -Port $port
    if ($null -ne $listener) {
        throw "Le port $port est déjà utilisé par le PID $listener."
    }
}

if (-not [string]::IsNullOrWhiteSpace($WazuhComposeRoot)) {
    $ComposeRoot = [System.IO.Path]::GetFullPath($WazuhComposeRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $ComposeRoot "compose.yml")) -and
        -not (Test-Path -LiteralPath (Join-Path $ComposeRoot "docker-compose.yml"))) {
        throw "Dossier Docker Compose Wazuh invalide : $ComposeRoot"
    }
    Push-Location $ComposeRoot
    try {
        & docker compose up -d
        if ($LASTEXITCODE -ne 0) {
            throw "Le démarrage de Wazuh a échoué."
        }
    }
    finally {
        Pop-Location
    }
}

New-Item -ItemType Directory -Force $RuntimeRoot | Out-Null

$Api = Start-Process -FilePath $PythonPath -ArgumentList "main.py" `
    -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $RuntimeRoot "api.stdout.log") `
    -RedirectStandardError (Join-Path $RuntimeRoot "api.stderr.log")

$DashboardArguments = @(
    "-m", "streamlit", "run", "src\alerting\dashboard.py",
    "--server.headless", "true",
    "--server.address", "127.0.0.1",
    "--server.port", "8501"
)
$Dashboard = Start-Process -FilePath $PythonPath -ArgumentList $DashboardArguments `
    -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $RuntimeRoot "dashboard.stdout.log") `
    -RedirectStandardError (Join-Path $RuntimeRoot "dashboard.stderr.log")

try {
    Wait-Http -Uri "http://127.0.0.1:8000/health" `
        -TimeoutSeconds $StartupTimeoutSeconds
    Wait-Http -Uri "http://127.0.0.1:8501/" `
        -TimeoutSeconds $StartupTimeoutSeconds
}
catch {
    Stop-Process -Id $Api.Id, $Dashboard.Id -Force -ErrorAction SilentlyContinue
    throw
}

[pscustomobject]@{
    api_pid = $Api.Id
    api_started_at = $Api.StartTime.ToUniversalTime().ToString("o")
    dashboard_pid = $Dashboard.Id
    dashboard_started_at = $Dashboard.StartTime.ToUniversalTime().ToString("o")
    project_root = $ProjectRoot
} | ConvertTo-Json | Set-Content -LiteralPath $PidPath -Encoding utf8

Write-Output "JANUS est prêt."
Write-Output "API       : http://127.0.0.1:8000"
Write-Output "Dashboard : http://127.0.0.1:8501"
Write-Output "Journaux  : $RuntimeRoot"

