# For the live S4U tests (client/s4u_ad_test.go): service accounts with
# delegation policy, in AES only. Needs the domain setup.ps1 made. Idempotent.
# The users' password comes from C:\Goose\dc\users.txt (one line), deleted
# once read, as setup.ps1 has it.
#
#   svc-proxy   HTTP/proxy.goose.test: protocol transition (TrustedToAuthFor-
#               Delegation), and constrained delegation to HTTP/target.goose.test
#   svc-kerb    HTTP/kerb.goose.test: constrained delegation to
#               HTTP/target.goose.test, without protocol transition
#   svc-self    HTTP/self.goose.test: no delegation at all
#   svc-target  HTTP/target.goose.test: svc-proxy's target
#   svc-rbcd    HTTP/rbcd.goose.test: no delegation of its own
#   svc-rbcdt   HTTP/rbcdt.goose.test: lets svc-rbcd delegate to it
#               (resource-based, PrincipalsAllowedToDelegateToAccount)
#   sens        a user with "account is sensitive and cannot be delegated"
#
#   powershell -ExecutionPolicy Bypass -File C:\Goose\scripts\s4u.ps1
param([string]$Domain = (Get-ADDomain).DNSRoot)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = (Get-ADDomain).DistinguishedName
$plain = (Get-Content C:\Goose\dc\users.txt -Raw).Trim()
Remove-Item C:\Goose\dc\users.txt -Force
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

function Ensure-User($name, $spn) {
    if (-not (Get-ADUser -Filter "sAMAccountName -eq '$name'")) {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@$Domain" `
            -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,$base"
    } else {
        Set-ADAccountPassword -Identity $name -NewPassword $pw -Reset
    }
    Set-ADUser -Identity $name -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }
    if ($spn) { Set-ADUser -Identity $name -ServicePrincipalNames @{ Replace = $spn } }
}

Ensure-User 'svc-proxy'  "HTTP/proxy.$Domain"
Ensure-User 'svc-kerb'   "HTTP/kerb.$Domain"
Ensure-User 'svc-self'   "HTTP/self.$Domain"
Ensure-User 'svc-target' "HTTP/target.$Domain"
Ensure-User 'svc-rbcd'   "HTTP/rbcd.$Domain"
Ensure-User 'svc-rbcdt'  "HTTP/rbcdt.$Domain"
Ensure-User 'sens'       $null

Set-ADAccountControl -Identity 'svc-proxy' -TrustedToAuthForDelegation $true
Set-ADUser -Identity 'svc-proxy' -Replace @{ 'msDS-AllowedToDelegateTo' = "HTTP/target.$Domain" }
Set-ADUser -Identity 'svc-kerb' -Replace @{ 'msDS-AllowedToDelegateTo' = "HTTP/target.$Domain" }
Set-ADUser -Identity 'svc-rbcdt' -PrincipalsAllowedToDelegateToAccount (Get-ADUser 'svc-rbcd')
Set-ADAccountControl -Identity 'sens' -AccountNotDelegated $true

foreach ($n in 'svc-proxy', 'svc-kerb', 'svc-self', 'svc-target', 'svc-rbcd', 'svc-rbcdt', 'sens') {
    Get-ADUser -Identity $n -Properties ServicePrincipalNames, TrustedToAuthForDelegation, AccountNotDelegated,
        'msDS-AllowedToDelegateTo', PrincipalsAllowedToDelegateToAccount |
        Select-Object SamAccountName, TrustedToAuthForDelegation, AccountNotDelegated,
            @{ n = 'SPN'; e = { $_.ServicePrincipalNames -join ',' } },
            @{ n = 'DelegateTo'; e = { $_.'msDS-AllowedToDelegateTo' -join ',' } },
            @{ n = 'RBCDFrom'; e = { $_.PrincipalsAllowedToDelegateToAccount -join ',' } } | Format-List
}
