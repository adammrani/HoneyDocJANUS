[CmdletBinding()]
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$GeneratedRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot "data\generated")).TrimEnd("\")
$TemplatePath = Join-Path $ProjectRoot "integrations\wazuh\janus_rules.template.xml"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot "data\janus_rules.xml"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

New-Item -ItemType Directory -Path $GeneratedRoot -Force | Out-Null
New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -Force | Out-Null
$EscapedRoot = [regex]::Escape($GeneratedRoot)
$Template = [System.IO.File]::ReadAllText($TemplatePath)
$Rendered = $Template.Replace("__JANUS_PATH_REGEX__", $EscapedRoot)
[System.IO.File]::WriteAllText($OutputPath, $Rendered, [System.Text.UTF8Encoding]::new($false))

Write-Output "Règles générées : $OutputPath"
Write-Output "Racine surveillée : $GeneratedRoot"
Write-Output "Copiez le fichier vers /var/ossec/etc/rules/local_rules.xml puis validez avec wazuh-analysisd -t."

