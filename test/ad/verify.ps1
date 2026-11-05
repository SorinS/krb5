# Read-only: is this host the DC the live tests need? One line per check,
# OK or MISSING, for the firewall, the KDC's policy and every account the
# tests use. Exits 1 if anything is missing. Changes nothing, needs no
# password.
param([string]$Domain = (Get-ADDomain).DNSRoot)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$script:bad = 0

function Check($what, $ok) {
    if ($ok) { "OK       $what" } else { "MISSING  $what"; $script:bad++ }
}

# AD's ports blocked from outside; ssh still let in.
foreach ($n in 'Goose: block AD (TCP)', 'Goose: block AD (UDP)') {
    $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
    Check "firewall: $n" ($r -and $r.Enabled -eq 'True' -and $r.Action -eq 'Block')
}

# The KDC's claims and armoring policy (setup.ps1).
$kdc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' -ErrorAction SilentlyContinue
Check 'KDC: EnableCbacAndArmor = 1' ($kdc -and $kdc.EnableCbacAndArmor -eq 1)
Check 'KDC: CbacAndArmorLevel = 1' ($kdc -and $kdc.CbacAndArmorLevel -eq 1)

function Account($name) {
    Get-ADUser -Filter "sAMAccountName -eq '$name'" -Properties ServicePrincipalNames, TrustedToAuthForDelegation,
        AccountNotDelegated, 'msDS-AllowedToDelegateTo', PrincipalsAllowedToDelegateToAccount,
        'msDS-SupportedEncryptionTypes', Department
}
function CheckUser($name, $etypes, $spns) {
    $u = Account $name
    Check "user $name" ($null -ne $u -and $u.Enabled)
    if ($null -eq $u) { return }
    Check "user ${name}: encryption types $etypes" ($u.'msDS-SupportedEncryptionTypes' -eq $etypes)
    foreach ($s in $spns) { Check "user ${name}: SPN $s" ($u.ServicePrincipalNames -contains $s) }
}

# setup.ps1: 0x18 AES, 0x1c AES and RC4, 0x60018 AES with claims and
# compound identity.
CheckUser 'alice' 0x18 @()
CheckUser 'bob' 0x1c @()
CheckUser 'svc-web' 0x60018 @("HTTP/web.$Domain", "host/web.$Domain")
Check 'alice: department' ((Account 'alice').Department -eq 'Engineering')
Check 'claim type department' ($null -ne (Get-ADClaimType -Filter "DisplayName -eq 'department'"))
$group = Get-ADGroup -Filter "Name -eq 'GooseTesters'"
Check 'group GooseTesters' ($null -ne $group)
if ($group) {
    $m = (Get-ADGroupMember -Identity 'GooseTesters').SamAccountName
    Check 'GooseTesters: alice and bob' (($m -contains 'alice') -and ($m -contains 'bob'))
}
$pc = Get-ADComputer -Filter "Name -eq 'goosepc'" -Properties 'msDS-SupportedEncryptionTypes'
Check 'computer goosepc$' ($null -ne $pc -and $pc.Enabled)
if ($pc) { Check 'goosepc$: AES only' ($pc.'msDS-SupportedEncryptionTypes' -eq 0x18) }

# claims.ps1: six string claims, enough for the KDC to compress.
CheckUser 'carol' 0x18 @()
foreach ($a in 'title', 'company', 'streetAddress', 'physicalDeliveryOfficeName', 'displayName', 'l') {
    Check "claim type goose-$a" ($null -ne (Get-ADClaimType -Filter "DisplayName -eq 'goose-$a'"))
}

# s4u.ps1: delegation policy.
foreach ($p in @(@('svc-proxy', 'proxy'), @('svc-kerb', 'kerb'), @('svc-self', 'self'),
                 @('svc-target', 'target'), @('svc-rbcd', 'rbcd'), @('svc-rbcdt', 'rbcdt'))) {
    CheckUser $p[0] 0x18 @("HTTP/$($p[1]).$Domain")
}
CheckUser 'sens' 0x18 @()
$target = "HTTP/target.$Domain"
Check 'svc-proxy: protocol transition' ((Account 'svc-proxy').TrustedToAuthForDelegation)
Check "svc-proxy: delegates to $target" ((Account 'svc-proxy').'msDS-AllowedToDelegateTo' -contains $target)
Check 'svc-kerb: no protocol transition' (-not (Account 'svc-kerb').TrustedToAuthForDelegation)
Check "svc-kerb: delegates to $target" ((Account 'svc-kerb').'msDS-AllowedToDelegateTo' -contains $target)
Check 'svc-self: no delegation' (-not (Account 'svc-self').TrustedToAuthForDelegation -and
    (Account 'svc-self').'msDS-AllowedToDelegateTo'.Count -eq 0)
Check 'svc-rbcdt: lets svc-rbcd delegate to it' ((Account 'svc-rbcdt').PrincipalsAllowedToDelegateToAccount -contains (Account 'svc-rbcd').DistinguishedName)
Check 'sens: cannot be delegated' ((Account 'sens').AccountNotDelegated)

Check 'keytab C:\Goose\dc\web.keytab' (Test-Path C:\Goose\dc\web.keytab)
Check 'no password file left behind' (-not ((Test-Path C:\Goose\dc\users.txt) -or (Test-Path C:\Goose\dc\p.txt) -or (Test-Path C:\Goose\dc_p.txt)))

"DC host name for TEST_AD_DC_HOST: $((Get-ADDomainController).HostName)"
if ($script:bad -gt 0) { "$script:bad missing"; exit 1 }
'all there'
