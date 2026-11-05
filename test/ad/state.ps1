# The host's network state before AD goes on it: DNS servers, interfaces
# (DHCP or not), the inbound rules that let ssh in, and what listens.
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { "dns: $($_.InterfaceAlias) $($_.ServerAddresses -join ',')" }
Get-NetIPConfiguration | ForEach-Object { "if: $($_.InterfaceAlias) gw=$($_.IPv4DefaultGateway.NextHop) dhcp=$((Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).Dhcp)" }
"firewall rules allowing inbound 22: " + (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -eq 22 } | Measure-Object).Count
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.DisplayName -like '*SSH*' } | Select-Object DisplayName,Profile | Format-Table -Auto
"listening:"; Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort -Unique | Sort-Object LocalPort | Format-Table -Auto
