# Schedule weekly compliance scan via Windows Task Scheduler
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = (Get-Command python).Source
$Action = New-ScheduledTaskAction -Execute $Python -Argument "-m compliance.run_scan --type scheduled" -WorkingDirectory $ProjectRoot
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "ARIA-ComplianceScan" -Action $Action -Trigger $Trigger -Description "Run ARIA Bank Milestone 7 compliance scan" -Force
Write-Host "Scheduled task ARIA-ComplianceScan registered."
