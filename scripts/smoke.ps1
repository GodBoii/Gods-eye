# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [uri]$BaseUrl = 'http://127.0.0.1:8765',
    [string]$SourceTarget = 'internal',
    [uri]$Website
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($BaseUrl.Scheme -ne 'http' -or $BaseUrl.Host -ne '127.0.0.1' -or
    $BaseUrl.AbsolutePath -ne '/' -or $BaseUrl.UserInfo -or $BaseUrl.Query -or $BaseUrl.Fragment) {
    throw 'The smoke test must connect to the local dashboard at http://127.0.0.1:PORT.'
}
if ($Website -and ($Website.Scheme -ne 'https' -or $Website.UserInfo -or $Website.Query -or $Website.Fragment)) {
    throw 'Website must be an explicitly authorized HTTPS URL without credentials or query parameters.'
}

$apiRoot = $BaseUrl.AbsoluteUri.TrimEnd('/')
$headers = @{ 'X-GodsEye-Request' = '1' }
$checks = [System.Collections.Generic.List[object]]::new()

function Invoke-Dashboard {
    param([string]$Path, [string]$Method = 'GET', [object]$Body)
    $options = @{ Uri = "$apiRoot$Path"; Method = $Method; Headers = $headers; TimeoutSec = 40 }
    if ($null -ne $Body) {
        $options.ContentType = 'application/json'
        $options.Body = ConvertTo-Json -InputObject $Body -Depth 8 -Compress
    }
    Invoke-RestMethod @options
}

function Assert-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $checks.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
    if (-not $Passed) { throw "$Name failed: $Detail" }
    Write-Host "PASS $Name"
}

function Start-Check {
    param([string]$Target, [string]$Kind = 'source')
    Invoke-Dashboard '/api/runs' 'POST' @{ target = $Target; kind = $Kind; authorized = $true }
}

function Wait-Check {
    param([string]$Id)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $result = Invoke-Dashboard "/api/runs/$Id"
        if ($result.status -notin @('running', 'cancelling')) { return $result }
        if ($timer.Elapsed.TotalSeconds -gt 35) { throw "Check $Id did not terminate within 35 seconds." }
        Start-Sleep -Milliseconds 100
    } while ($true)
}

function Save-Report {
    param([string]$Id, [string]$Format, [string]$File)
    Invoke-WebRequest "$apiRoot/api/runs/$Id/report?format=$Format" -Headers $headers -TimeoutSec 20 -OutFile $File
    Get-Content -LiteralPath $File -Raw
}

$initial = Invoke-Dashboard '/api/state'
if (@($initial.runs | Where-Object { $_.status -in @('running', 'cancelling') }).Count -gt 0) {
    throw 'Wait for the active check to finish before running the smoke test.'
}
$workspace = [System.IO.Path]::GetFullPath($initial.workspace)
$testId = [guid]::NewGuid().ToString('N')
$relative = ".godseye/smoke-$testId"
$testRoot = Join-Path $workspace $relative
$candidateDir = Join-Path $testRoot 'candidates'
$binaryDir = Join-Path $testRoot 'binary'
$cancelDir = Join-Path $testRoot 'cancellation'
foreach ($directory in @($testRoot, $candidateDir, $binaryDir, $cancelDir)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$testAssetId = $null

try {
    $created = Invoke-Dashboard '/api/assets' 'POST' @{
        name = "Smoke fixture $testId"; kind = 'source'; target = "$relative/candidates"; owner = 'Automated verification'
    }
    $testAssetId = $created.id
    $inventory = Invoke-Dashboard '/api/state'
    Assert-Check 'Inventory registration' (@($inventory.assets | Where-Object { $_.id -eq $testAssetId }).Count -eq 1) 'Temporary asset appears in the saved inventory.'

    if ($Website) {
        $started = Start-Check $Website.AbsoluteUri 'website'
        $remote = Wait-Check $started.id
        $remote | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $testRoot 'website.json')
        Assert-Check 'Live website checker' ($remote.status -eq 'completed' -and @($remote.checks).Count -ge 4) $remote.status
    }

    # The full Earth source distribution also contains binary models and large datasets.
    # Exercise the native source directory; binary omissions are tested explicitly below.
    $started = Start-Check $SourceTarget
    $source = Wait-Check $started.id
    Assert-Check 'Real codebase scan' ($source.status -eq 'completed' -and $source.files -gt 0) "$($source.files) files, $($source.findingCount) candidates."
    $null = Save-Report $source.id 'json' (Join-Path $testRoot 'codebase.json')
    $null = Save-Report $source.id 'sarif' (Join-Path $testRoot 'codebase.sarif')

    # These deliberately invalid synthetic candidates are never sent to the website.
    $github = 'ghp_' + ('Q' * 36)
    $aws = 'AKIA' + ('Q' * 16)
    $keyMarker = '-----BEGIN ' + 'PRIVATE KEY-----'
    [System.IO.File]::WriteAllText((Join-Path $candidateDir 'synthetic.txt'), "$github`n$aws`n$keyMarker`n")
    $started = Start-Check "$relative/candidates"
    $candidate = Wait-Check $started.id
    Assert-Check 'All three secret rules' ($candidate.status -eq 'completed' -and $candidate.findingCount -eq 3) "$($candidate.findingCount) synthetic candidates detected."
    foreach ($format in @('json', 'sarif')) {
        $text = Save-Report $candidate.id $format (Join-Path $testRoot "candidates.$format")
        $document = $text | ConvertFrom-Json
        Assert-Check "$format credential redaction" (-not ($text.Contains($github) -or $text.Contains($aws) -or $text.Contains($keyMarker))) 'Credential content is absent from the report.'
        if ($format -eq 'sarif') {
            Assert-Check 'SARIF result mapping' ($document.version -eq '2.1.0' -and @($document.runs[0].results).Count -eq 3) 'Three results have standard SARIF output.'
        }
    }

    [System.IO.File]::WriteAllBytes((Join-Path $binaryDir 'sample.bin'), [byte[]](0, 1, 2, 3))
    $started = Start-Check "$relative/binary"
    $partial = Wait-Check $started.id
    Assert-Check 'Incomplete coverage reporting' ($partial.status -eq 'partial' -and @($partial.gaps).Count -gt 0) 'A binary omission is not reported as a clean completed scan.'

    $payload = [System.Text.Encoding]::UTF8.GetBytes(('ordinary source text ' * 1700))
    for ($index = 0; $index -lt 512; $index++) {
        [System.IO.File]::WriteAllBytes((Join-Path $cancelDir ('source-{0:D4}.txt' -f $index)), $payload)
    }
    $started = Start-Check "$relative/cancellation"
    $null = Invoke-Dashboard "/api/runs/$($started.id)/cancel" 'POST'
    $cancelled = Wait-Check $started.id
    Assert-Check 'Live scan cancellation' ($cancelled.status -eq 'cancelled') $cancelled.status

    $binary = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin/godseye.exe'
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Build bin/godseye.exe before running the CLI checks.' }
    $limitedFile = Join-Path $testRoot 'limited.json'
    & $binary scan --max-findings 1 --out $limitedFile $candidateDir
    Assert-Check 'CLI limit exit code' ($LASTEXITCODE -eq 3) 'A truncated scan exits with code 3.'
    $limited = Get-Content -Raw -LiteralPath $limitedFile | ConvertFrom-Json
    Assert-Check 'CLI finding limit' (@($limited.findings).Count -eq 1 -and $limited.summary.status -eq 'RUN_STATUS_PARTIAL') 'One candidate retained with partial coverage.'
    $before = Get-FileHash -LiteralPath $limitedFile -Algorithm SHA256
    & $binary scan --out $limitedFile $candidateDir
    $overwriteExit = $LASTEXITCODE
    $after = Get-FileHash -LiteralPath $limitedFile -Algorithm SHA256
    Assert-Check 'CLI overwrite protection' ($overwriteExit -eq 2 -and $before.Hash -eq $after.Hash) 'The existing report is unchanged.'
} finally {
    if ($testAssetId) {
        $null = Invoke-Dashboard "/api/assets/$testAssetId" 'DELETE'
        $remaining = Invoke-Dashboard '/api/state'
        Assert-Check 'Inventory removal' (@($remaining.assets | Where-Object { $_.id -eq $testAssetId }).Count -eq 0) 'Only the temporary test asset was removed.'
    }
    $checks | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $testRoot 'checks.json')
    Write-Host "Evidence directory: $testRoot"
}

# The overwrite check intentionally receives native exit code 2. A successful
# smoke run must not leak that expected rejection into its caller's exit status.
$global:LASTEXITCODE = 0
