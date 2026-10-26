<#
.SYNOPSIS
  Installs Send-WindowsEvents.ps1 as a Windows scheduled task (runs at startup as SYSTEM, restarts on failure).
.DESCRIPTION
  Requires an elevated PowerShell. The ingest key is stored in a machine-level environment variable
  (SIEM_INGEST_KEY) restricted by the task running as SYSTEM; rotate it by re-running this script.
  Uninstall:  .\Install-WindowsCollector.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [string]$ApiUrl = 'http://localhost:8080',
  [string]$ApiKey,
  [int[]]$EventIds = @(4624, 4625, 4634, 4672, 4688, 4720, 4740, 5156, 7045),
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$taskName = 'SIEM Windows Event Forwarder'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated (Administrator) PowerShell.' }

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host 'Task removed (bookmarks in %ProgramData%\SiemCollector were kept).'
  return
}
if (-not $ApiKey) { throw 'Provide -ApiKey (one of SIEM_INGEST_API_KEYS).' }

$dest = Join-Path $env:ProgramFiles 'SiemCollector'
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'Send-WindowsEvents.ps1') $dest -Force
[Environment]::SetEnvironmentVariable('SIEM_INGEST_KEY', $ApiKey, 'Machine')

$ids = ($EventIds -join ',')
$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$dest\Send-WindowsEvents.ps1`" -ApiUrl $ApiUrl -LogName Security -EventIds $ids"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed and started '$taskName'. Verify: Get-ScheduledTask '$taskName' | Get-ScheduledTaskInfo ; then check Admin > Collectors in the UI." -ForegroundColor Green
