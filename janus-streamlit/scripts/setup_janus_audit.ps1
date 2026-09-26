[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ouvrez PowerShell en tant qu'administrateur."
}

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$AllowedRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot "data\generated")).TrimEnd("\")
New-Item -ItemType Directory -Path $AllowedRoot -Force | Out-Null

$Acl = Get-Acl -LiteralPath $AllowedRoot -Audit
$Sid = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
$Rights = [System.Security.AccessControl.FileSystemRights]::ReadData `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [System.Security.AccessControl.FileSystemRights]::Delete
$Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
    -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$AuditFlags = [System.Security.AccessControl.AuditFlags]::Success
$Existing = $Acl.GetAuditRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
) | Where-Object {
    $_.IdentityReference.Value -eq $Sid.Value -and
    ($_.FileSystemRights -band $Rights) -eq $Rights -and
    ($_.InheritanceFlags -band $Inheritance) -eq $Inheritance
} | Select-Object -First 1

if ($null -eq $Existing) {
    $Rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
        $Sid,
        $Rights,
        $Inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        $AuditFlags
    )
    $Acl.AddAuditRule($Rule)
    Set-Acl -LiteralPath $AllowedRoot -AclObject $Acl
    Write-Output "SACL JANUS ajoutée à $AllowedRoot."
}
else {
    Write-Output "SACL JANUS déjà présente sur $AllowedRoot."
}

