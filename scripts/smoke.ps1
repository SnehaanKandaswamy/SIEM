<#
.SYNOPSIS  End-to-end smoke test against a running stack: login -> ingest -> detect -> search -> metrics.
  Exits non-zero on the first failed check.
#>
param([ValidateSet('dev', 'prod')][string]$Mode = 'dev', [string]$BaseUrl)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
if ((Test-Path $dockerBin) -and ($env:Path -notlike "*$dockerBin*")) { $env:Path += ";$dockerBin" }

$envMap = @{}
Get-Content .env | ForEach-Object { if ($_ -match '^\s*([A-Z0-9_]+)=(.*)$') { $envMap[$matches[1]] = $matches[2] } }
if (-not $BaseUrl) { $BaseUrl = "http://localhost:$($envMap['SIEM_HTTP_PORT'])" }
$script:fail = 0
function Check([string]$name, [scriptblock]$test) {
  try { $r = & $test; if ($r -eq $false) { throw 'assertion false' }; Write-Host "PASS  $name" -ForegroundColor Green }
  catch { Write-Host "FAIL  $name :: $($_.Exception.Message)" -ForegroundColor Red; $script:fail++ }
}

Check 'frontend serves the SPA' { (Invoke-WebRequest "$BaseUrl/" -UseBasicParsing).Content -match 'id="root"' }
Check 'API rejects unauthenticated requests' {
  try { Invoke-RestMethod "$BaseUrl/api/alerts" | Out-Null; $false } catch { $_.Exception.Response.StatusCode.value__ -eq 401 }
}
Check 'ingestion rejects bad key' {
  try { Invoke-RestMethod "$BaseUrl/api/ingest" -Method Post -Headers @{ 'X-Ingest-Key' = 'nope' } -ContentType 'application/json' -Body '{"records":[{"message":"x"}]}' | Out-Null; $false } catch { $_.Exception.Response.StatusCode.value__ -eq 401 }
}
Check 'metrics are not exposed through the public proxy' {
  try { Invoke-WebRequest "$BaseUrl/metrics" -UseBasicParsing | Out-Null; $false } catch { $_.Exception.Response.StatusCode.value__ -eq 404 }
}
$login = $null
Check 'administrator can log in' {
  $body = @{ username = $envMap['SIEM_BOOTSTRAP_ADMIN_USERNAME']; password = $envMap['SIEM_BOOTSTRAP_ADMIN_PASSWORD'] } | ConvertTo-Json
  $script:login = Invoke-RestMethod "$BaseUrl/api/auth/login" -Method Post -ContentType 'application/json' -Body $body
  $script:login.role -eq 'admin'
}
$H = @{ Authorization = "Bearer $($script:login.access_token)" }
Check 'synthetic events ingest, detect and alert (through the nginx proxy)' {
  $out = & docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend sh -c 'python -m app.demo --url http://frontend:8080 --key "${SIEM_INGEST_API_KEYS%%,*}"'
  Write-Host "      $out"
  ($out -join '') -match '^200 ' -and ($out -join '') -match '"rejected":\s*0'
}
Check 'all five detection rules produced alerts' {
  $a = Invoke-RestMethod "$BaseUrl/api/alerts?size=100" -Headers $H
  $rules = ($a.items | ForEach-Object { $_.rule_id } | Sort-Object -Unique) -join ','
  Write-Host "      rules with alerts: $rules"
  $rules -eq 'SIEM-001,SIEM-002,SIEM-003,SIEM-004,SIEM-005'
}
Check 'full-text search finds the encoded PowerShell command' {
  Start-Sleep 2
  (Invoke-RestMethod "$BaseUrl/api/events/search?q=powershell" -Headers $H).total -ge 1
}
Check 'dashboard overview reflects ingested data' { (Invoke-RestMethod "$BaseUrl/api/dashboard/overview" -Headers $H).events_total -gt 0 }
Check 'MITRE view lists T1110 and T1046' {
  $t = (Invoke-RestMethod "$BaseUrl/api/mitre" -Headers $H).techniques.technique_id
  ($t -contains 'T1110') -and ($t -contains 'T1046')
}
Check 'CSV and PDF reports download' {
  $csv = Invoke-WebRequest "$BaseUrl/api/reports/alerts?format=csv" -Headers $H -UseBasicParsing
  $pdf = Invoke-WebRequest "$BaseUrl/api/reports/alerts?format=pdf" -Headers $H -UseBasicParsing
  ($csv.Content -match 'SIEM-001') -and ($pdf.Content.Length -gt 1000)
}
Check 'Prometheus scrapes the backend' {
  $t = (& docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T prometheus wget -qO- 'http://localhost:9090/api/v1/targets') -join '' | ConvertFrom-Json
  $up = $t.data.activeTargets | Where-Object { $_.labels.job -eq 'siem-backend' -and $_.health -eq 'up' }
  [bool]$up
}
Check 'Grafana is healthy and has the SIEM dashboard' {
  $auth = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:$($envMap['GRAFANA_ADMIN_PASSWORD'])")) }
  $s = Invoke-RestMethod "http://localhost:$($envMap['GRAFANA_PORT'])/api/search?query=SIEM" -Headers $auth
  $s.title -contains 'SIEM - Operations'
}
if ($script:fail -gt 0) { Write-Host "`n$($script:fail) check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nAll smoke checks passed." -ForegroundColor Green
