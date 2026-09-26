[CmdletBinding()]
param(
    [switch]$InstallDependencies,
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ExamplePath = Join-Path $ProjectRoot ".env.example"
$EnvPath = Join-Path $ProjectRoot ".env"

if (-not (Test-Path -LiteralPath $ExamplePath)) {
    throw "Modèle .env.example introuvable : $ExamplePath"
}

if (-not (Test-Path -LiteralPath $EnvPath)) {
    Copy-Item -LiteralPath $ExamplePath -Destination $EnvPath
    Write-Output ".env créé depuis .env.example."
}
else {
    Write-Output ".env existant conservé."
}

function Set-DotEnvValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        [void]$lines.Add($line)
    }
    $prefix = "$Name="
    $found = $false
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index].StartsWith($prefix, [StringComparison]::Ordinal)) {
            $lines[$index] = "$prefix$Value"
            $found = $true
            break
        }
    }
    if (-not $found) {
        [void]$lines.Add("$prefix$Value")
    }
    [System.IO.File]::WriteAllLines(
        $Path,
        $lines,
        [System.Text.UTF8Encoding]::new($false)
    )
}

$currentKey = ""
foreach ($line in [System.IO.File]::ReadAllLines($EnvPath)) {
    if ($line.StartsWith("JANUS_ADMIN_API_KEY=", [StringComparison]::Ordinal)) {
        $currentKey = $line.Substring("JANUS_ADMIN_API_KEY=".Length).Trim()
        break
    }
}

if ([string]::IsNullOrWhiteSpace($currentKey)) {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    $generatedKey = ([BitConverter]::ToString($bytes)).Replace("-", "")
    Set-DotEnvValue -Path $EnvPath -Name "JANUS_ADMIN_API_KEY" -Value $generatedKey
    Write-Output "Clé d'administration JANUS générée dans .env (valeur non affichée)."
}
else {
    Write-Output "Clé d'administration JANUS existante conservée."
}

foreach ($relativePath in @("data", "data\shared", "data\deployed_docs")) {
    New-Item -ItemType Directory -Path (Join-Path $ProjectRoot $relativePath) -Force |
        Out-Null
}

if ($InstallDependencies) {
    & $PythonExe -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Installation des dépendances Python échouée."
    }
}

Write-Output "Initialisation JANUS terminée."
Write-Output "Démarrage API : $PythonExe main.py"
Write-Output "Dashboard : streamlit run src\alerting\dashboard.py"
