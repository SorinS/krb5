# Blocks AD's ports from outside, then installs the AD DS role. Run it
# before promote.ps1: block rules win over the allow rules the promotion
# adds. Loopback is not filtered, so ssh tunnels to 127.0.0.1 still reach
# the KDC and LDAP. Run it again at any time; it replaces its rules.
$tcp = @('53','88','135','139','389','445','464','593','636','3268','3269','5722','9389','49152-65535')
$udp = @('53','88','123','137','138','389','464','500','4500')
Remove-NetFirewallRule -DisplayName 'Goose: block AD (TCP)' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Goose: block AD (UDP)' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Goose: block AD (TCP)' -Direction Inbound -Action Block -Protocol TCP -LocalPort $tcp -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'Goose: block AD (UDP)' -Direction Inbound -Action Block -Protocol UDP -LocalPort $udp -Profile Any | Out-Null
Get-NetFirewallRule -DisplayName 'Goose: block AD*' | Select-Object DisplayName,Enabled,Action,Direction | Format-Table -Auto
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Select-Object Success,RestartNeeded,ExitCode | Format-List
