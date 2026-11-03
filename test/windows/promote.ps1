# Makes this host the first DC of a new forest, then reboots. Run by
# schedule.ps1 as SYSTEM, so the promotion survives the ssh session that
# started it. The DSRM password comes from C:\Goose\dc\p.txt, deleted once
# read. The log is C:\Goose\dc\promote.log.
param(
    [string]$Domain = 'goose.test',
    [string]$NetBios = 'GOOSE'
)
Start-Transcript -Path C:\Goose\dc\promote.log -Force
Unregister-ScheduledTask -TaskName 'GoosePromote' -Confirm:$false -ErrorAction SilentlyContinue
$pw = ConvertTo-SecureString ((Get-Content C:\Goose\dc\p.txt -Raw).Trim()) -AsPlainText -Force
Remove-Item C:\Goose\dc\p.txt -Force
Import-Module ADDSDeployment
Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBios -InstallDns -SafeModeAdministratorPassword $pw `
    -DomainMode WinThreshold -ForestMode WinThreshold -NoRebootOnCompletion:$false -Force
Stop-Transcript
