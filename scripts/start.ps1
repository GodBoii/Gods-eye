param([switch]$Build)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$nodeExe = if ($nodeCommand) { $nodeCommand.Source } elseif (Test-Path 'C:\Program Files\nodejs\node.exe') { 'C:\Program Files\nodejs\node.exe' } else { throw 'Install Node.js 24.14 or newer first.' }
$earthRoot = Join-Path $projectRoot 'apps/earth'
$dashboardRoot = Join-Path $projectRoot 'apps/web'
$stateRoot = Join-Path $projectRoot '.godseye'
New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
if ($Build) {
    $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
    $npmExe = if ($npmCommand) { $npmCommand.Source } elseif (Test-Path 'C:\Program Files\nodejs\npm.cmd') { 'C:\Program Files\nodejs\npm.cmd' } else { throw 'npm is required to build.' }
    foreach ($appRoot in @($dashboardRoot, $earthRoot)) {
        Push-Location -LiteralPath $appRoot
        try {
            & $npmExe ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed in $appRoot" }
            & $npmExe run build
            if ($LASTEXITCODE -ne 0) { throw "Build failed in $appRoot" }
        } finally { Pop-Location }
    }
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    $goExe = if ($goCommand) { $goCommand.Source } else { Join-Path $env:LOCALAPPDATA 'GodsEye/tools/go/bin/go.exe' }
    if (!(Test-Path -LiteralPath $goExe)) { throw 'Install Go 1.25 or newer to build the dashboard server.' }
    Push-Location -LiteralPath $projectRoot
    try {
        New-Item -ItemType Directory -Path (Join-Path $projectRoot 'bin') -Force | Out-Null
        & $goExe build -o bin/godseye.exe ./cmd/godseye
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard server build failed.' }
    } finally { Pop-Location }
}
$dashboardExe = Join-Path $projectRoot 'bin/godseye.exe'
if (!(Test-Path -LiteralPath $dashboardExe) -or !(Test-Path -LiteralPath (Join-Path $earthRoot 'dist/index.html')) -or !(Test-Path -LiteralPath (Join-Path $dashboardRoot 'dist/index.html'))) { throw 'Build the applications first with ./scripts/start.ps1 -Build.' }
foreach ($port in @(8765, 4173)) {
    $alreadyRunning = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    if ($alreadyRunning) {
        if ($port -eq 8765) {
            try { $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8765/api/health' -TimeoutSec 3 } catch {
                throw 'Port 8765 contains an older or unrelated service. Stop that service, then rebuild and restart Gods Eye. The frontend and backend must use the same build.'
            }
            if ($health.service -ne 'godseye' -or $health.capabilities -notcontains 'tool-assessments-v1') {
                throw 'The running dashboard is incompatible with this frontend. Stop the old service, then rebuild and restart Gods Eye.'
            }
        }
        Write-Host "Port $port is already listening. Reusing the verified running service."
        continue
    }
    if ($port -eq 8765) {
        $process = Start-Process -FilePath $dashboardExe -ArgumentList @('serve','--root','.') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $stateRoot 'dashboard.log') -RedirectStandardError (Join-Path $stateRoot 'dashboard-error.log')
    } else {
        $process = Start-Process -FilePath $nodeExe -ArgumentList @('node_modules/vite/bin/vite.js','preview','--host','127.0.0.1','--port','4173') -WorkingDirectory $earthRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $stateRoot 'earth.log') -RedirectStandardError (Join-Path $stateRoot 'earth-error.log')
    }
    Write-Host "Started local service on port $port, process $($process.Id)."
}
Write-Host 'Security workspace: http://127.0.0.1:8765'
Write-Host 'Earth console:      http://127.0.0.1:4173'
