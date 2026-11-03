# For the live PAC claims tests: the user carol (AES only) with claims
# large enough that the KDC compresses her ClaimsSet (LZ77+Huffman,
# MS-ADTS 2.2.18.5): claim types on six string attributes, each with a long
# value. Needs the domain setup.ps1 made (claims support on). Idempotent.
# The users' password comes from C:\Goose\dc\users.txt (one line), deleted
# once read, as setup.ps1 has it.
#
#   powershell -ExecutionPolicy Bypass -File C:\Goose\scripts\claims.ps1
param([string]$Domain = (Get-ADDomain).DNSRoot)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = (Get-ADDomain).DistinguishedName
$plain = (Get-Content C:\Goose\dc\users.txt -Raw).Trim()
Remove-Item C:\Goose\dc\users.txt -Force
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

if (-not (Get-ADUser -Filter "sAMAccountName -eq 'carol'")) {
    New-ADUser -Name 'carol' -SamAccountName 'carol' -UserPrincipalName "carol@$Domain" `
        -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,$base"
} else {
    Set-ADAccountPassword -Identity 'carol' -NewPassword $pw -Reset
}
Set-ADUser -Identity 'carol' -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }

# The attributes, the claim types' ids, and carol's values (repetitive
# enough to compress, as real directory data is).
$attrs = 'title', 'company', 'streetAddress', 'physicalDeliveryOfficeName', 'displayName', 'l'
$values = @{}
foreach ($a in $attrs) {
    if (-not (Get-ADClaimType -Filter "DisplayName -eq 'goose-$a'")) {
        New-ADClaimType -DisplayName "goose-$a" -SourceAttribute $a -ID "ad://ext/$($a):goose" `
            -AppliesToClasses user | Out-Null
    }
    # 64 characters: company's limit (title, office and l take 128).
    $values[$a] = ("carol's ${a}: " + ("value of $a, compressed claims " * 3)).Substring(0, 64)
}
Set-ADUser -Identity 'carol' -Title $values['title'] -Company $values['company'] `
    -StreetAddress $values['streetAddress'] -Office $values['physicalDeliveryOfficeName'] `
    -DisplayName $values['displayName'] -City $values['l']
foreach ($a in $attrs) { "$a = $($values[$a])" }
