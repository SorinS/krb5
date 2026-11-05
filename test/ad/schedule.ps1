# Starts promote.ps1 as SYSTEM from a scheduled task. Copy first: the
# scripts into C:\Goose\scripts, and the DSRM password to C:\Goose\dc_p.txt
# (one line).
param(
    [string]$Domain = 'goose.test',
    [string]$NetBios = 'GOOSE'
)
New-Item -ItemType Directory -Force -Path C:\Goose\dc | Out-Null
Move-Item -Force C:\Goose\dc_p.txt C:\Goose\dc\p.txt
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Goose\scripts\promote.ps1 -Domain $Domain -NetBios $NetBios"
Register-ScheduledTask -TaskName 'GoosePromote' -Action $a -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'GoosePromote'
"started: C:\Goose\dc\promote.log; the host reboots when it is done"
