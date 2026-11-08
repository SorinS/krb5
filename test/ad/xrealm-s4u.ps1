# For the live cross-realm S4U2Proxy test (client/s4u_ad_test.go): on one of
# two forests with a two-way trust, each provisioned with s4u.ps1, a target
# the other forest's svc-proxy may delegate to. Across a trust only
# resource-based delegation does: svc-xtarget's
# msDS-AllowedToActOnBehalfOfOtherIdentity names svc-proxy by its SID, which
# this forest cannot look up without the peer's credentials, so it is given.
# Run it on both forests, each with the other's svc-proxy's SID
# ((Get-ADUser svc-proxy).SID.Value there). Idempotent. The users' password
# comes from C:\Goose\dc\users.txt (one line), deleted once read, as
# setup.ps1 has it.
#
#   svc-xtarget  HTTP/xtarget.<domain>: lets the peer's svc-proxy delegate to it
#
#   powershell -ExecutionPolicy Bypass -File C:\Goose\scripts\xrealm-s4u.ps1 -ProxySID S-1-5-21-...
param(
    [Parameter(Mandatory = $true)][string]$ProxySID,
    [string]$Domain = (Get-ADDomain).DNSRoot
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = (Get-ADDomain).DistinguishedName
$plain = (Get-Content C:\Goose\dc\users.txt -Raw).Trim()
Remove-Item C:\Goose\dc\users.txt -Force
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

$sid = New-Object System.Security.Principal.SecurityIdentifier $ProxySID

if (-not (Get-ADUser -Filter "sAMAccountName -eq 'svc-xtarget'")) {
    New-ADUser -Name 'svc-xtarget' -SamAccountName 'svc-xtarget' -UserPrincipalName "svc-xtarget@$Domain" `
        -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,$base"
} else {
    Set-ADAccountPassword -Identity 'svc-xtarget' -NewPassword $pw -Reset
}
Set-ADUser -Identity 'svc-xtarget' -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }
Set-ADUser -Identity 'svc-xtarget' -ServicePrincipalNames @{ Replace = "HTTP/xtarget.$Domain" }

# The security descriptor PrincipalsAllowedToDelegateToAccount writes, for a
# SID of another forest.
$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid.Value))"
$bytes = New-Object byte[] $sd.BinaryLength
$sd.GetBinaryForm($bytes, 0)
Set-ADUser -Identity 'svc-xtarget' -Replace @{ 'msDS-AllowedToActOnBehalfOfOtherIdentity' = $bytes }

$u = Get-ADUser -Identity 'svc-xtarget' -Properties ServicePrincipalNames, 'msDS-AllowedToActOnBehalfOfOtherIdentity'
$allowed = $u.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access | ForEach-Object { $_.IdentityReference.Value }
"svc-xtarget: $($u.ServicePrincipalNames -join ', '); may be delegated to by $($allowed -join ', ')"
