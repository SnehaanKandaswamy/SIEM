<#
.SYNOPSIS
  Windows-friendly entry point for the SIEM Dashboard stack (Docker Desktop + WSL2).
.DESCRIPTION
  .\scripts\siem.ps1 <command> [-Mode dev|prod]
  Commands: setup | up | down | status | logs | migrate | demo | smoke | test | backup | restore | reset | doctor
  'down' never deletes volumes. 'reset' deletes ALL data and requires typing the project name.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][ValidateSet('setup', 'up', 'down', 'status', 'logs', 'migrate', 'demo', 'smoke', 'test', 'backup', 'restore', 'reset', 'doctor')]
  [string]$Command = 'doctor',
  [Parameter(Position = 1)][string]$Arg,
  [ValidateSet('dev', 'prod')][string]$Mode = 'dev'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Make docker available even if Docker Desktop was installed in this same shell session.
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
if ((Test-Path $dockerBin) -and ($env:Path -notlike "*$dockerBin*")) { $env:Path += ";$dockerBin" }

function Get-ComposeArgs {
  $a = @('compose', '-f', 'docker-compose.yml')
  if ($Mode -eq 'prod') { $a += @('-f', 'docker-compose.prod.yml') } else { $a += @('-f', 'docker-compose.dev.yml') }
  return $a
}
function Invoke-Compose { param([string[]]$Rest) & docker @(Get-ComposeArgs) @Rest; if ($LASTEXITCODE -ne 0) { throw "docker compose $($Rest -join ' ') failed (exit $LASTEXITCODE)" } }
function New-Secret([int]$bytes = 32) {
  $b = New-Object byte[] $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return ([Convert]::ToBase64String($b) -replace '[^A-Za-z0-9]', '').Substring(0, [Math]::Min($bytes, 40))
}
function Read-DotEnv {
  $h = @{}
  if (Test-Path .env) { Get-Content .env | ForEach-Object { if ($_ -match '^\s*([A-Z0-9_]+)=(.*)$') { $h[$matches[1]] = $matches[2] } } }
  return $h
}

switch ($Command) {
  'doctor' {
    Write-Host '== Environment checks ==' -ForegroundColor Cyan
    $ok = $true
    try { $v = docker version --format '{{.Server.Version}}' 2>$null; if (-not $v) { throw 'no daemon' }; Write-Host "Docker daemon: $v" } catch { Write-Host 'Docker daemon NOT reachable. Start Docker Desktop and wait for it to say "running".' -ForegroundColor Red; $ok = $false }
    try { $c = docker compose version --short 2>$null; Write-Host "Docker Compose: $c" } catch { Write-Host 'docker compose missing' -ForegroundColor Red; $ok = $false }
    $mem = [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    Write-Host "Host RAM: $mem GB (8 GB minimum, 16 GB recommended)"
    if ($mem -lt 8) { Write-Host 'Low memory: set OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m in .env' -ForegroundColor Yellow }
    $free = [Math]::Round((Get-PSDrive -Name ($Root.Substring(0, 1))).Free / 1GB, 1)
    Write-Host "Free disk on $($Root.Substring(0,1)): $free GB (20 GB recommended)"
    try {
      $mm = (wsl -d docker-desktop sysctl -n vm.max_map_count 2>$null)
      if ($mm -and [int]$mm -ge 262144) { Write-Host "vm.max_map_count: $mm (ok for OpenSearch)" }
      else { Write-Host "vm.max_map_count is '$mm' (< 262144). Run: wsl -d docker-desktop sysctl -w vm.max_map_count=262144   (see docs/DEPLOYMENT.md to persist)" -ForegroundColor Yellow }
    } catch { Write-Host 'Could not query the docker-desktop WSL distro (is the WSL2 backend enabled?)' -ForegroundColor Yellow }
    foreach ($p in 8080, 3000) { if (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) { Write-Host "Port $p already in use - change SIEM_HTTP_PORT / GRAFANA_PORT in .env" -ForegroundColor Yellow } }
    if (-not (Test-Path .env)) { Write-Host '.env missing: run .\scripts\siem.ps1 setup' -ForegroundColor Yellow }
    if (-not $ok) { exit 1 }
  }
  'setup' {
    if (Test-Path .env) { Write-Host '.env already exists - leaving it untouched.'; break }
    $key = New-Secret 40
    $adminPw = New-Secret 24
    $text = Get-Content .env.example -Raw
    $text = $text -replace 'POSTGRES_PASSWORD=CHANGE_ME', "POSTGRES_PASSWORD=$(New-Secret 32)"
    $text = $text -replace 'SIEM_JWT_SECRET=CHANGE_ME_AT_LEAST_32_RANDOM_CHARS', "SIEM_JWT_SECRET=$(New-Secret 40)$(New-Secret 40)"
    $text = $text -replace 'GRAFANA_ADMIN_PASSWORD=CHANGE_ME', "GRAFANA_ADMIN_PASSWORD=$(New-Secret 24)"
    $text = $text -replace 'CHANGE_ME_COLLECTOR_KEY', $key
    $text = $text -replace 'SIEM_BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME_MIN_12_CHARS', "SIEM_BOOTSTRAP_ADMIN_PASSWORD=$adminPw"
    if ($Mode -eq 'dev') { $text = $text -replace 'SIEM_ALLOW_DEMO_ENDPOINTS=false', 'SIEM_ALLOW_DEMO_ENDPOINTS=true' }
    Set-Content -Path .env -Value $text -Encoding ascii
    Write-Host 'Created .env with freshly generated secrets (never commit it).' -ForegroundColor Green
    Write-Host "Administrator login:  admin / $adminPw   (also stored in .env; change it after first login)"
  }
  'up' {
    if (-not (Test-Path .env)) { throw '.env missing. Run: .\scripts\siem.ps1 setup' }
    Invoke-Compose @('up', '-d', '--build', '--wait', '--wait-timeout', '600')
    $e = Read-DotEnv
    Write-Host "SIEM UI:  http://localhost:$($e['SIEM_HTTP_PORT'])    Grafana: http://localhost:$($e['GRAFANA_PORT'])" -ForegroundColor Green
  }
  'down' { Invoke-Compose @('down', '--remove-orphans'); Write-Host 'Stopped. Volumes (your data) were kept.' }
  'status' { Invoke-Compose @('ps') }
  'logs' { if ($Arg) { Invoke-Compose @('logs', '--tail', '200', '-f', $Arg) } else { Invoke-Compose @('logs', '--tail', '100') } }
  'migrate' { Invoke-Compose @('run', '--rm', 'migrate') }
  'demo' {
    # Posts the deterministic synthetic scenarios through the real ingestion API.
    $scenario = if ($Arg) { $Arg } else { 'all' }
    Invoke-Compose @('exec', '-T', 'backend', 'sh', '-c', "python -m app.demo --url http://localhost:8000 --key `"`${SIEM_INGEST_API_KEYS%%,*}`" --scenario $scenario")
  }
  'smoke' { & "$PSScriptRoot\smoke.ps1" -Mode $Mode }
  'test' {
    $py = Join-Path $Root 'backend\.venv\Scripts\python.exe'
    if (-not (Test-Path $py)) { python -m venv backend\.venv; & $py -m pip install -q -r backend\requirements-dev.txt }
    Push-Location backend; & $py -m ruff check .; & $py -m ruff format --check .; & $py -m pytest -q; $rc = $LASTEXITCODE; Pop-Location
    if ($rc -ne 0) { throw 'backend tests failed' }
    Push-Location frontend; if (-not (Test-Path node_modules)) { npm ci }; npm run lint; npm run format; npm test; $rc = $LASTEXITCODE; Pop-Location
    if ($rc -ne 0) { throw 'frontend tests failed' }
  }
  'backup' { & "$PSScriptRoot\backup.ps1" -Mode $Mode }
  'restore' { & "$PSScriptRoot\restore.ps1" -Mode $Mode -BackupName $Arg }
  'reset' {
    Write-Host 'This DELETES all SIEM data volumes (PostgreSQL, OpenSearch, Grafana, Prometheus).' -ForegroundColor Red
    $c = Read-Host 'Type "siem" to confirm'
    if ($c -ne 'siem') { Write-Host 'Aborted.'; break }
    Invoke-Compose @('down', '-v', '--remove-orphans')
  }
}
