<#
.SYNOPSIS
  Forwards Windows Event Log records to the SIEM ingestion API (no third-party agent required).
.DESCRIPTION
  Reads events with Get-WinEvent, converts each to the SIEM Windows JSON shape (EventID, Channel, Computer,
  TimeCreated, EventData{name=value}) and POSTs batches to /api/ingest with the X-Ingest-Key header.
  * Security log requires an elevated PowerShell (or membership of "Event Log Readers").
  * Failed logons (4625) need "Audit Logon" failure auditing; command lines in 4688 need
    "Include command line in process creation events" (see docs/DEPLOYMENT.md).
  * A bookmark file keeps the last forwarded RecordId so restarts do not resend or lose events.
.EXAMPLE
  $env:SIEM_INGEST_KEY = '<collector key>'
  .\Send-WindowsEvents.ps1 -ApiUrl http://localhost:8080 -LogName Security -EventIds 4624,4625,4688,4720 -Once
#>
[CmdletBinding()]
param(
  [string]$ApiUrl = 'http://localhost:8080',
  [string]$ApiKey = $env:SIEM_INGEST_KEY,
  [string]$LogName = 'Security',
  [int[]]$EventIds,
  [int]$IntervalSeconds = 15,
  [int]$BatchSize = 200,
  [int]$InitialLookbackMinutes = 5,
  [string]$BookmarkDir = (Join-Path $env:ProgramData 'SiemCollector'),
  [switch]$Once,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if (-not $ApiKey -and -not $DryRun) { throw 'Set -ApiKey or $env:SIEM_INGEST_KEY' }
New-Item -ItemType Directory -Force $BookmarkDir | Out-Null
$safeName = $LogName -replace '[^A-Za-z0-9]', '_'
$bookmark = Join-Path $BookmarkDir "$safeName.recordid"

function ConvertTo-SiemRecord($e) {
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = [string]$d.'#text' } }
  [ordered]@{
    source_type = 'windows'
    EventID     = [int]$e.Id
    Channel     = $e.LogName
    Computer    = $e.MachineName
    TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
    EventData   = $data
  }
}

function Send-Batch($records) {
  if ($DryRun) { $records | ConvertTo-Json -Depth 6 | Write-Output; return }
  $body = @{ source_type = 'windows'; host = $env:COMPUTERNAME; records = $records } | ConvertTo-Json -Depth 8 -Compress
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
      $r = Invoke-RestMethod -Uri "$ApiUrl/api/ingest" -Method Post -ContentType 'application/json; charset=utf-8' `
        -Headers @{ 'X-Ingest-Key' = $ApiKey; 'X-Collector' = "winlog-$env:COMPUTERNAME" } -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30
      Write-Host ("{0} sent={1} indexed={2} rejected={3} alerts={4}" -f (Get-Date -Format s), $records.Count, $r.indexed, $r.rejected, $r.alerts_created)
      return
    } catch {
      $wait = [Math]::Min(2 * $attempt, 20)
      Write-Warning "Send failed ($($_.Exception.Message)); retry $attempt/5 in ${wait}s"
      Start-Sleep $wait
    }
  }
  throw 'Giving up after 5 attempts; bookmark not advanced so these events will be resent.'
}

do {
  $filter = @{ LogName = $LogName }
  if ($EventIds) { $filter.Id = $EventIds }
  $last = if (Test-Path $bookmark) { [int64](Get-Content $bookmark) } else { 0 }
  if ($last -eq 0) { $filter.StartTime = (Get-Date).AddMinutes(-$InitialLookbackMinutes) }
  try { $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
  catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
    elseif ($_.Exception -is [System.UnauthorizedAccessException]) { throw "Access denied reading '$LogName'. Run PowerShell as Administrator." }
    else { throw }
  }
  $events = $events | Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
  for ($i = 0; $i -lt $events.Count; $i += $BatchSize) {
    $chunk = @($events[$i..([Math]::Min($i + $BatchSize, $events.Count) - 1)])
    Send-Batch @($chunk | ForEach-Object { ConvertTo-SiemRecord $_ })
    if (-not $DryRun) { Set-Content -Path $bookmark -Value ($chunk[-1].RecordId) }
  }
  if (-not $Once) { Start-Sleep $IntervalSeconds }
} while (-not $Once)
