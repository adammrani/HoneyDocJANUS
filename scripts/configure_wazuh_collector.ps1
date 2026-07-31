[CmdletBinding()]
param(
    [string]$IndexerUrl = "https://localhost:9200",
    [string]$Username = "admin",
    [string]$RuleId = "100100",
    [string]$ForensicAgentIds = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$DevelopmentTrustSelfSigned
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..")
)
$ExamplePath = Join-Path $ProjectRoot ".env.example"
$EnvPath = Join-Path $ProjectRoot ".env"

if (-not (Test-Path -LiteralPath $ExamplePath -PathType Leaf)) {
    throw "Fichier .env.example introuvable : $ExamplePath"
}

if (Test-Path -LiteralPath $EnvPath -PathType Leaf) {
    $BackupPath = "$EnvPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $EnvPath -Destination $BackupPath
    Write-Output "Configuration précédente sauvegardée : $BackupPath"
}
else {
    Copy-Item -LiteralPath $ExamplePath -Destination $EnvPath
}

if ($null -eq $Credential) {
    $Credential = Get-Credential `
        -UserName $Username `
        -Message "Identifiants de Wazuh Indexer pour JANUS"
}
if ($null -eq $Credential) {
    throw "Configuration annulée : aucun identifiant fourni."
}

$PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
    $Credential.Password
)
try {
    $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        $PasswordPointer
    )
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
}

if ([string]::IsNullOrWhiteSpace($PlainPassword)) {
    throw "Le mot de passe Wazuh Indexer ne peut pas être vide."
}
if ($PlainPassword.Contains("`r") -or $PlainPassword.Contains("`n")) {
    throw "Le mot de passe ne peut pas contenir de saut de ligne."
}

function Format-DotEnvValue([string]$Value) {
    $Escaped = $Value.Replace("\", "\\").Replace('"', '\"')
    return '"' + $Escaped + '"'
}

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

Set-DotEnvValue $Lines "WAZUH_AUTO_COLLECT_ENABLED" "true"
Set-DotEnvValue $Lines "WAZUH_INDEXER_URL" (Format-DotEnvValue $IndexerUrl)
Set-DotEnvValue $Lines "WAZUH_INDEXER_USERNAME" (
    Format-DotEnvValue $Credential.UserName
)
Set-DotEnvValue $Lines "WAZUH_INDEXER_PASSWORD" (
    Format-DotEnvValue $PlainPassword
)
Set-DotEnvValue $Lines "WAZUH_RULE_ID" (Format-DotEnvValue $RuleId)
Set-DotEnvValue $Lines "WAZUH_ADDITIONAL_RULE_IDS" (
    Format-DotEnvValue "100101,100102,100103,100104"
)
Set-DotEnvValue $Lines "FORENSIC_TELEMETRY_ENABLED" "true"
Set-DotEnvValue $Lines "FORENSIC_AGENT_IDS" (
    Format-DotEnvValue $ForensicAgentIds
)
$VerifySsl = if ($DevelopmentTrustSelfSigned) { "false" } else { "true" }
Set-DotEnvValue $Lines "WAZUH_VERIFY_SSL" $VerifySsl

[System.IO.File]::WriteAllLines(
    $EnvPath,
    $Lines,
    [System.Text.UTF8Encoding]::new($false)
)
$PlainPassword = $null

Write-Output "Collecteur Wazuh activé dans : $EnvPath"
Write-Output "Indexer : $IndexerUrl"
Write-Output "Règle : $RuleId"
Write-Output "Télémétrie Windows/Linux activée. Agents : $ForensicAgentIds"
if ($DevelopmentTrustSelfSigned) {
    Write-Warning (
        "La validation TLS est désactivée pour ce laboratoire local. " +
        "Configurez WAZUH_CA_CERT_PATH avant un déploiement réel."
    )
}
Write-Output "Redémarrez l'API JANUS pour charger la configuration."
