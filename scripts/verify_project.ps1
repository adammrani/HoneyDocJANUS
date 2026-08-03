[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$TestRoot = Join-Path $ProjectRoot "data\pytest-temp"

Push-Location $ProjectRoot
try {
    & $PythonExe -m compileall -q src main.py scenarios
    if ($LASTEXITCODE -ne 0) {
        throw "Compilation Python échouée."
    }

    & $PythonExe -m pytest -q -p no:cacheprovider --basetemp $TestRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Tests Python échoués."
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File scripts\configure_wazuh_rule.ps1 -RenderOnly
    if ($LASTEXITCODE -ne 0) {
        throw "Génération de la règle Wazuh échouée."
    }
    [void][xml](Get-Content -Raw -LiteralPath data\wazuh\janus_rules.xml)

    if (-not $SkipDocker -and (Get-Command docker -ErrorAction SilentlyContinue)) {
        & docker compose config --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Configuration Docker Compose invalide."
        }
    }

    Write-Output "Validation JANUS réussie."
}
finally {
    Pop-Location
}
