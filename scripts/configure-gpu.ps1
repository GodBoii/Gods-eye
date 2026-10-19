#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Inspect', 'Apply', 'Restore')]
    [string]$Mode = 'Inspect',
    [string[]]$BrowserPath
)

$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Windows graphics preferences require Windows.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$backupPath = Join-Path $projectRoot '.godseye/gpu-preferences.json'
$registryPath = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'

function Get-GraphicsPreference([string]$Executable) {
    if (!(Test-Path -LiteralPath $registryPath)) { return $null }
    $key = Get-Item -LiteralPath $registryPath
    try { return $key.GetValue($Executable, $null) }
    finally { $key.Close() }
}

$backup = @{ version = 1; entries = @{} }
if (Test-Path -LiteralPath $backupPath) {
    $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json -AsHashtable
    if ($backup.version -ne 1 -or $backup.entries -isnot [System.Collections.IDictionary]) {
        throw "Invalid graphics preference backup: $backupPath"
    }
    foreach ($entry in $backup.entries.GetEnumerator()) {
        if (![IO.Path]::IsPathFullyQualified($entry.Key) -or
            ($null -ne $entry.Value -and $entry.Value -isnot [string])) {
            throw "Invalid graphics preference backup entry: $backupPath"
        }
    }
}

if ($Mode -eq 'Restore') {
    if (!(Test-Path -LiteralPath $backupPath)) { throw 'No saved graphics preferences to restore.' }
    if ($BrowserPath) { throw 'Restore uses the saved executable paths; omit BrowserPath.' }
    foreach ($executable in @($backup.entries.Keys)) {
        if (!$PSCmdlet.ShouldProcess($executable, 'Restore saved Windows graphics preference')) { continue }
        if ($null -eq $backup.entries[$executable]) {
            if (Test-Path -LiteralPath $registryPath) {
                $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\DirectX\UserGpuPreferences', $true)
                try { $key.DeleteValue($executable, $false) }
                finally { $key.Close() }
            }
        } else {
            if (!(Test-Path -LiteralPath $registryPath)) { New-Item -Path $registryPath | Out-Null }
            New-ItemProperty -LiteralPath $registryPath -Name $executable -Value $backup.entries[$executable] -PropertyType String -Force | Out-Null
        }
        $backup.entries.Remove($executable)
        $backup | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupPath -Encoding utf8
        Write-Host "Restored $executable"
    }
    return
}

if (!$BrowserPath) {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft/Edge/Application/msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft/Edge/Application/msedge.exe'),
        (Join-Path $env:ProgramFiles 'Google/Chrome/Application/chrome.exe'),
        (Join-Path $env:LOCALAPPDATA 'Google/Chrome/Application/chrome.exe')
    )
    $BrowserPath = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}
if (!$BrowserPath) { throw 'No supported browser found. Supply its full executable path with -BrowserPath.' }

# Resolve every input before changing any preferences.
$executables = @($BrowserPath | ForEach-Object {
    $item = Get-Item -LiteralPath $_
    if ($item.PSIsContainer -or $item.Extension -ne '.exe') { throw "Expected a browser executable: $_" }
    $item.FullName
} | Sort-Object -Unique)

$applied = 0
foreach ($executable in $executables) {
    $previous = Get-GraphicsPreference $executable
    if ($null -ne $previous -and $previous -isnot [string]) { throw "Unexpected registry value type for $executable" }
    if ($Mode -eq 'Inspect') {
        [pscustomobject]@{ Executable = $executable; Preference = $previous ?? 'Windows default' }
        continue
    }
    if (!$PSCmdlet.ShouldProcess($executable, 'Prefer the high-performance GPU for this browser')) { continue }
    if (!$backup.entries.Contains($executable)) {
        $backup.entries[$executable] = $previous
        New-Item -ItemType Directory -Path (Split-Path -Parent $backupPath) -Force | Out-Null
        # Save the original before changing Windows, including an absent value.
        $backup | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupPath -Encoding utf8
    }
    # Preserve unrelated per-application flags such as Auto HDR preferences.
    $flags = @(([string]$previous -split ';') | Where-Object { $_ -and $_ -notmatch '^\s*GpuPreference\s*=' })
    $value = (@($flags) + 'GpuPreference=2') -join ';'
    if (!(Test-Path -LiteralPath $registryPath)) { New-Item -Path $registryPath | Out-Null }
    New-ItemProperty -LiteralPath $registryPath -Name $executable -Value "$value;" -PropertyType String -Force | Out-Null
    $applied++
    Write-Host "High-performance GPU preferred: $executable"
}
if ($applied -gt 0) {
    Write-Host 'Fully exit and reopen these browsers to apply the preference. Windows selects the high-performance GPU.'
    Write-Host "Original preferences saved in $backupPath. Restore with ./scripts/configure-gpu.ps1 -Mode Restore."
}
