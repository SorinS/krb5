# After promotion: what the krb5 tests need in the domain. Idempotent.
#   - users alice (AES only) and bob (AES and RC4), in the group GooseTesters;
#   - the service account svc-web with SPN HTTP/web.<domain> (and its
#     host/ name), AES only, its keytab written by ktpass;
#   - the KDC's claims support turned on, a claim type on `department`,
#     and alice's department set, for the PAC's claims;
#   - the service accepts claims and compound identity
#     (msDS-SupportedEncryptionTypes bits 18 and 17);
#   - the computer account goosepc$ (AES only), the device whose TGT armors
#     a TGS request for compound identity, with the users' password.
# The users' password comes from C:\Goose\dc\users.txt (one line), deleted
# once read. The keytab is C:\Goose\dc\web.keytab; copy it back with scp.
param([string]$Domain = (Get-ADDomain).DNSRoot)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$realm = $Domain.ToUpper()
$base = (Get-ADDomain).DistinguishedName
$plain = (Get-Content C:\Goose\dc\users.txt -Raw).Trim()
Remove-Item C:\Goose\dc\users.txt -Force
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

# AES128 0x8, AES256 0x10, RC4 0x4; compound identity supported 0x20000,
# claims supported 0x40000.
function Ensure-User($name, $etypes) {
    if (-not (Get-ADUser -Filter "sAMAccountName -eq '$name'")) {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@$Domain" `
            -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,$base"
    } else {
        Set-ADAccountPassword -Identity $name -NewPassword $pw -Reset
    }
    Set-ADUser -Identity $name -Replace @{ 'msDS-SupportedEncryptionTypes' = $etypes }
}
Ensure-User 'alice' 0x18
Ensure-User 'bob' 0x1c
Ensure-User 'svc-web' (0x18 -bor 0x20000 -bor 0x40000)

if (-not (Get-ADComputer -Filter "Name -eq 'goosepc'")) {
    New-ADComputer -Name 'goosepc' -SamAccountName 'goosepc$' -DNSHostName "goosepc.$Domain" -AccountPassword $pw -Enabled $true
} else {
    Set-ADAccountPassword -Identity 'goosepc$' -NewPassword $pw -Reset
}
Set-ADComputer -Identity 'goosepc$' -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }

if (-not (Get-ADGroup -Filter "Name -eq 'GooseTesters'")) {
    New-ADGroup -Name 'GooseTesters' -GroupScope Global -GroupCategory Security -Path "CN=Users,$base"
}
Add-ADGroupMember -Identity 'GooseTesters' -Members 'alice','bob'

$host_ = "web.$Domain"
Set-ADUser -Identity 'svc-web' -ServicePrincipalNames @{ Replace = "HTTP/$host_", "host/$host_" }

# Claims (Dynamic Access Control): the KDC issues claims when the policy
# "KDC support for claims, compound authentication and Kerberos armoring"
# is on (EnableCbacAndArmor, level 1 = supported). Set as the policy's
# registry values; a GPO would do the same domain-wide.
$kdc = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
New-Item -Path $kdc -Force | Out-Null
Set-ItemProperty -Path $kdc -Name EnableCbacAndArmor -Value 1 -Type DWord
Set-ItemProperty -Path $kdc -Name CbacAndArmorLevel -Value 1 -Type DWord
if (-not (Get-ADClaimType -Filter "DisplayName -eq 'department'")) {
    New-ADClaimType -DisplayName 'department' -SourceAttribute department -ID 'ad://ext/department:goose' `
        -AppliesToClasses user | Out-Null
}
Set-ADUser -Identity 'alice' -Department 'Engineering'

# The service's keytab: AES256 under its SPN, the account's password reset
# to the users' one (-pass) so the key is known to the tests too. ktpass
# also sets the account's UPN to the SPN, so that AD's AES salt and the
# one ktpass derives the key with agree (the usual ktpass pitfall; check it
# with `goose-krb5 kvno` and `klist -k`); -mapop add keeps the host/ SPN.
$netbios = (Get-ADDomain).NetBIOSName
# ktpass prints the key; its output goes nowhere (through cmd: with
# ErrorActionPreference Stop, PowerShell stops at a native command's
# redirected stderr).
cmd /c "ktpass -out C:\Goose\dc\web.keytab -princ HTTP/$host_@$realm -mapuser $netbios\svc-web -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass $plain -mapop add >NUL 2>&1"
if ($LASTEXITCODE -ne 0) { throw "ktpass failed: $LASTEXITCODE" }
"keytab: C:\Goose\dc\web.keytab"

# The KDC reads the claims policy at start.
Restart-Service kdc -Force
Get-ADUser -Filter "Name -like '*'" -SearchBase "CN=Users,$base" -Properties servicePrincipalName,'msDS-SupportedEncryptionTypes',memberOf |
    Where-Object { $_.SamAccountName -in 'alice','bob','svc-web' } |
    Select-Object SamAccountName,UserPrincipalName,servicePrincipalName,'msDS-SupportedEncryptionTypes' | Format-List
Get-ADComputer -Identity 'goosepc$' -Properties 'msDS-SupportedEncryptionTypes' |
    Select-Object SamAccountName,DNSHostName,'msDS-SupportedEncryptionTypes' | Format-List
