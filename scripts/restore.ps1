<#
.SYNOPSIS  Restore PostgreSQL + OpenSearch from a backup created by backup.ps1 (folder name under .\backups-local).
.NOTES     DESTRUCTIVE for current data: PostgreSQL objects are dropped/recreated and matching OpenSearch indices are
           replaced. Confirmation is required.
#>
param([ValidateSet('dev', 'prod')][string]$Mode = 'dev', [Parameter(Mandatory)][string]$BackupName, [switch]$Force)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
if ((Test-Path $dockerBin) -and ($env:Path -notlike "*$dockerBin*")) { $env:Path += ";$dockerBin" }
$files = @('-f', 'docker-compose.yml', '-f', $(if ($Mode -eq 'prod') { 'docker-compose.prod.yml' } else { 'docker-compose.dev.yml' }))
function DC { & docker compose @files @args; if ($LASTEXITCODE -ne 0) { throw "docker compose $args failed" } }
$envMap = @{}; Get-Content .env | ForEach-Object { if ($_ -match '^\s*([A-Z0-9_]+)=(.*)$') { $envMap[$matches[1]] = $matches[2] } }

# OpenSearch REST helper. The whole command line is built for `sh -c` inside the container; embedded double quotes are
# backslash-escaped because Windows PowerShell 5.1 does not quote native-command arguments correctly.
function OS([string]$Method, [string]$Path, [string]$Body = '') {
  $url = if ($Mode -eq 'prod') { "https://localhost:9200$Path" } else { "http://localhost:9200$Path" }
  $cmd = "curl -s -X $Method '$url'"
  if ($Mode -eq 'prod') { $cmd += " -k -u 'admin:$($envMap['OPENSEARCH_ADMIN_PASSWORD'])'" }
  if ($Body) { $cmd += " -H 'Content-Type: application/json' -d '$Body'" }
  $out = & docker compose @files exec -T opensearch sh -c ($cmd -replace '"', '\"')
  if ($LASTEXITCODE -ne 0) { throw "OpenSearch request $Method $Path failed" }
  return ($out -join '')
}

$dir = Join-Path $Root "backups-local\$BackupName"
if (-not (Test-Path (Join-Path $dir 'MANIFEST.txt'))) { throw "No valid backup at $dir" }
$m = @{}; Get-Content (Join-Path $dir 'MANIFEST.txt') | ForEach-Object { $k, $v = $_ -split '=', 2; $m[$k] = $v }
if (-not $Force) { $c = Read-Host "Restore $BackupName over the CURRENT data? Type 'restore' to continue"; if ($c -ne 'restore') { Write-Host 'Aborted.'; return } }

Write-Host '== Stopping writers (backend, fluent-bit)'
DC stop backend fluent-bit frontend | Out-Null

Write-Host '== Staging backup files into the backups volume'
& docker run --rm -v siem_backups:/b -v "${dir}:/in:ro" alpine:3.20 sh -c 'cp -a /in/. /b/'
if ($LASTEXITCODE -ne 0) { throw 'staging failed' }

Write-Host '== PostgreSQL restore'
DC exec -T postgres pg_restore -U siem -d siem --clean --if-exists --no-owner "/backups/$($m['postgres'])"

Write-Host '== OpenSearch restore'
DC exec -T -u root opensearch sh -c 'chown -R 1000:1000 /snapshots/os'
OS PUT '/_snapshot/siem_fs' '{"type":"fs","settings":{"location":"/snapshots/os"}}' | Out-Null
OS DELETE '/siem-events-*' | Out-Null
$r = OS POST "/_snapshot/siem_fs/$($m['opensearch_snapshot'])/_restore?wait_for_completion=true" '{"indices":"siem-events-*","include_global_state":false}'
Write-Host $r

Write-Host '== Restarting services'
DC up -d --wait backend frontend fluent-bit | Out-Null
Write-Host 'Restore complete. Verify with: .\scripts\siem.ps1 smoke   and compare event/alert counts (docs/DEPLOYMENT.md#recovery-verification).' -ForegroundColor Green
