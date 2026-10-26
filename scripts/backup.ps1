<#
.SYNOPSIS  Back up PostgreSQL (pg_dump) and OpenSearch (fs snapshot) and copy both to .\backups-local\<timestamp>\ on the host.
.NOTES     The 'backups' Docker volume is only a staging area. A volume is NOT a backup: keep the host copy
           (and ideally a copy on another machine / object storage).
#>
param([ValidateSet('dev', 'prod')][string]$Mode = 'dev')
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

$ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
Write-Host "== PostgreSQL dump ($ts)"
DC exec -T postgres sh -c "pg_dump -U siem -Fc siem > /backups/pg-$ts.dump && ls -l /backups/pg-$ts.dump"

Write-Host '== OpenSearch snapshot'
DC exec -T -u root opensearch sh -c 'mkdir -p /snapshots/os && chown -R 1000:1000 /snapshots/os'
OS PUT '/_snapshot/siem_fs' '{"type":"fs","settings":{"location":"/snapshots/os"}}' | Out-Null
$snapRaw = OS PUT "/_snapshot/siem_fs/snap-$($ts.ToLower())?wait_for_completion=true" '{"indices":"siem-events-*","ignore_unavailable":true,"include_global_state":false}'
$snapJson = $snapRaw | ConvertFrom-Json
if ($snapJson.snapshot.state -ne 'SUCCESS') { throw "OpenSearch snapshot failed: $snapRaw" }
Write-Host "snapshot snap-$($ts.ToLower()) : $($snapJson.snapshot.state), $($snapJson.snapshot.shards.successful) shard(s), indices: $($snapJson.snapshot.indices -join ',')"

Write-Host '== Copying to host'
$out = Join-Path $Root "backups-local\$ts"
New-Item -ItemType Directory -Force $out | Out-Null
& docker run --rm -v siem_backups:/b:ro -v "${out}:/out" alpine:3.20 sh -c 'cp -a /b/. /out/'
if ($LASTEXITCODE -ne 0) { throw 'copy to host failed' }
Set-Content -Path (Join-Path $out 'MANIFEST.txt') -Value "created=$ts`npostgres=pg-$ts.dump`nopensearch_snapshot=snap-$($ts.ToLower())"
Write-Host "Backup complete: $out" -ForegroundColor Green
