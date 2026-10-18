param(
    [switch]$Build,
    [ValidateRange(1, 65535)][int]$Port = 8766,
    [string]$Root = '',
    [string]$State = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot 'backend'
$pythonExe = Join-Path $backendRoot '.venv/Scripts/python.exe'
$webRoot = Join-Path $projectRoot 'apps/web'
$webDist = Join-Path $webRoot 'dist'
if ($Port -eq 8765) { throw 'This migration candidate uses an alternate port until all feature parity gates pass.' }
$scanRoot = if ($Root) { (Resolve-Path -LiteralPath $Root).Path } else { $projectRoot }
$candidateState = if ($State) { [System.IO.Path]::GetFullPath($State) } else { Join-Path $projectRoot '.godseye/python-preview' }
$legacyState = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.godseye'))
if ($candidateState.TrimEnd('\', '/') -eq $legacyState.TrimEnd('\', '/')) { throw 'Use an isolated state copy. The migration candidate must not write the Go state directory.' }

if ($Build) {
    if (!(Test-Path -LiteralPath $pythonExe)) {
        $pythonCommand = Get-Command python -ErrorAction Stop
        & $pythonCommand.Source -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 13) else 2)'
        if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.13 first.' }
        & $pythonCommand.Source -m venv (Join-Path $backendRoot '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
    }
    & $pythonExe -m pip install --require-hashes -r (Join-Path $backendRoot 'requirements.lock')
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
    & $pythonExe -m pip install --no-deps --editable $backendRoot
    if ($LASTEXITCODE -ne 0) { throw 'Python backend installation failed.' }
    $npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
    Push-Location -LiteralPath $webRoot
    try {
        & $npmExe ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard dependency installation failed.' }
        & $npmExe run build
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed.' }
    } finally { Pop-Location }
}
if (!(Test-Path -LiteralPath $pythonExe) -or !(Test-Path -LiteralPath (Join-Path $webDist 'index.html'))) {
    throw 'Run ./scripts/start-python.ps1 -Build first.'
}
New-Item -ItemType Directory -Path $candidateState -Force | Out-Null
$healthUrl = "http://127.0.0.1:$Port/api/health"
$listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
if ($listener) {
    try { $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 3 } catch {
        throw "Port $Port contains an unrelated service. Choose another candidate port."
    }
    if ($health.service -ne 'godseye' -or $health.runtime -ne 'python' -or $health.version -ne '0.5.0.dev1' -or $health.capabilities -notcontains 'source-scans-v1') {
        throw "Port $Port does not contain this Python candidate. Choose another candidate port."
    }
    Write-Host "Python candidate already running at http://127.0.0.1:$Port"
    return
}
$arguments = @('-m', 'godseye', 'serve', '--root', "`"$scanRoot`"", '--state', "`"$candidateState`"", '--web', "`"$webDist`"", '--port', $Port)
$process = Start-Process -FilePath $pythonExe -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $candidateState 'server.log') -RedirectStandardError (Join-Path $candidateState 'server-error.log')
$ready = $false
$deadline = [DateTime]::UtcNow.AddSeconds(15)
while ([DateTime]::UtcNow -lt $deadline) {
    $process.Refresh()
    if ($process.HasExited) { throw 'Python candidate exited during startup. Read server-error.log in its isolated state directory.' }
    try {
        $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 1
        if ($health.runtime -eq 'python' -and $health.version -eq '0.5.0.dev1' -and $health.capabilities -contains 'source-scans-v1') {
            $ready = $true
            break
        }
    } catch { Start-Sleep -Milliseconds 100 }
}
if (!$ready) {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    throw 'Python candidate did not become ready within 15 seconds.'
}
Write-Host "Python candidate: http://127.0.0.1:$Port, process $($process.Id)"
Write-Host 'Available: inventory, source scans, cancellation, JSON and SARIF exports.'
Write-Host 'Workbench, HTTPS checks and World feeds remain migration work. Earth starts separately.'
