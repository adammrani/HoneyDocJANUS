[CmdletBinding()]
param(
    [string]$Path = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..")
)
$AllowedRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $ProjectRoot "data\shared")
).TrimEnd("\")
$RequestedPath = if ([string]::IsNullOrWhiteSpace($Path)) {
    $AllowedRoot
}
else {
    $Path
}
$CanonicalPath = [System.IO.Path]::GetFullPath($RequestedPath).TrimEnd("\")

if (-not $CanonicalPath.Equals(
    $AllowedRoot,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Chemin refusé par la liste blanche : $CanonicalPath"
}

New-Item -ItemType Directory -Path $CanonicalPath -Force | Out-Null

$Acl = Get-Acl -LiteralPath $CanonicalPath -Audit
$Sid = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
$Rights = [System.Security.AccessControl.FileSystemRights]::ReadData `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [System.Security.AccessControl.FileSystemRights]::Delete
$Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
    -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$AuditFlags = [System.Security.AccessControl.AuditFlags]::Success

$ExistingRule = $Acl.GetAuditRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
) | Where-Object {
    $_.IdentityReference.Value -eq $Sid.Value -and
    ($_.FileSystemRights -band $Rights) -eq $Rights -and
    ($_.InheritanceFlags -band $Inheritance) -eq $Inheritance -and
    ($_.AuditFlags -band $AuditFlags) -eq $AuditFlags
} | Select-Object -First 1

if ($null -eq $ExistingRule) {
    $Rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
        $Sid,
        $Rights,
        $Inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        $AuditFlags
    )
    $Acl.AddAuditRule($Rule)
    Set-Acl -LiteralPath $CanonicalPath -AclObject $Acl
    Write-Output "SACL JANUS ajoutée à $CanonicalPath."
}
else {
    Write-Output "SACL JANUS déjà présente sur $CanonicalPath."
}

(Get-Acl -LiteralPath $CanonicalPath -Audit).GetAuditRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
) | Where-Object {
    $_.IdentityReference.Value -eq $Sid.Value
} | Select-Object `
    IdentityReference,
    FileSystemRights,
    AuditFlags,
    InheritanceFlags,
    PropagationFlags,
    IsInherited
