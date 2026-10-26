<#
.SYNOPSIS  Windows-specific validation of the host: PowerShell, Docker Desktop/WSL2, ports, .env loading, volumes.
  Prints PASS/FAIL per check and exits non-zero on any failure. Run before and after `siem.ps1 up`.
#>
param([switch]$StackRunning)
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
if ((Test-Path $dockerBin) -and ($env:Path -notlike "*$dockerBin*")) { $env:Path += ";$dockerBin" }
$script:fail = 0
function Check([string]$name, [scriptblock]$t) {
  try { $r = & $t; if ($r -eq $false) { throw 'false' }; Write-Host "PASS  $name" -ForegroundColor Green }
  catch { Write-Host "FAIL  $name :: $($_.Exception.Message)" -ForegroundColor Red; $script:fail++ }
}
Check "Windows version ($([Environment]::OSVersion.Version))" { [Environment]::OSVersion.Platform -eq 'Win32NT' }
Check "PowerShell $($PSVersionTable.PSVersion) (5.1+)" { $PSVersionTable.PSVersion.Major -ge 5 }
Check 'repository is not on a path with unsupported characters' { $Root -notmatch '[&;|<>]' }
Check 'Docker CLI present' { [bool](Get-Command docker -ErrorAction Stop) }
Check 'Docker daemon reachable (Docker Desktop running)' { (docker version --format '{{.Server.Version}}' 2>$null) -ne $null }
Check 'Docker Desktop uses Linux containers (WSL2 backend)' { (docker info --format '{{.OSType}}' 2>$null) -eq 'linux' }
Check 'WSL2 distro docker-desktop is running' { (wsl -l -v 2>$null | Out-String) -replace "`0", '' -match 'docker-desktop\s+Running\s+2' }
Check 'vm.max_map_count >= 262144 (OpenSearch)' { [int](wsl -d docker-desktop sysctl -n vm.max_map_count 2>$null) -ge 262144 }
Check 'compose files validate' { docker compose -f docker-compose.yml -f docker-compose.dev.yml config -q 2>$null; $LASTEXITCODE -eq 0 }
Check '.env exists and loads without CHANGE_ME placeholders' {
  $lines = Get-Content .env | Where-Object { $_ -notmatch '^\s*#' }; $t = $lines -join "`n"; ($t -notmatch '=CHANGE_ME') -and ($t -match 'SIEM_JWT_SECRET=\S{32,}')
}
Check '.env is git-ignored' { (Get-Content .gitignore) -contains '.env' }
if ($StackRunning) {
  $e = @{}; Get-Content .env | ForEach-Object { if ($_ -match '^\s*([A-Z0-9_]+)=(.*)$') { $e[$matches[1]] = $matches[2] } }
  Check "UI port $($e['SIEM_HTTP_PORT']) answers on loopback" { (Invoke-WebRequest "http://127.0.0.1:$($e['SIEM_HTTP_PORT'])/nginx-health" -UseBasicParsing).StatusCode -eq 200 }
  Check 'UI port is bound to loopback only (not 0.0.0.0)' {
    $l = Get-NetTCPConnection -LocalPort ([int]$e['SIEM_HTTP_PORT']) -State Listen -ErrorAction Stop
    -not ($l | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' })
  }
  Check 'PostgreSQL/OpenSearch/Prometheus not reachable from the LAN interfaces' {
    foreach ($p in 5432, 9200, 9090) { $l = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; if ($l | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' }) { throw "port $p listens on all interfaces" } }
  }
  Check 'named volumes exist (data persisted outside containers)' {
    $v = docker volume ls --format '{{.Name}}'; ('siem_pgdata', 'siem_osdata') | ForEach-Object { if ($v -notcontains $_) { throw "missing $_" } }
  }
}
if ($script:fail) { Write-Host "$($script:fail) Windows check(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'Windows host checks passed.' -ForegroundColor Green
