# =============================================================================
# Restore test (restic) for Windows endpoints/servers
# =============================================================================
# CIS IG1 11.3 - Test backup restoration. Restores the canary file from the
# latest snapshot into a temp directory and compares its SHA-256 with the value
# recorded by backup.ps1 outside the repository.
#
# Metric written only on success:
#   backup_last_restore_test_timestamp_seconds{job,host}
#
# Schedule weekly (Task Scheduler, SYSTEM). Same environment as backup.ps1.
# =============================================================================

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TextfileDir = 'C:\Program Files\windows_exporter\textfile_inputs',
    [string]$Job = 'restic'
)

$ErrorActionPreference = 'Stop'

function Write-TextfileMetric {
    param([string]$FileName, [string]$Body)
    New-Item -ItemType Directory -Force -Path $TextfileDir | Out-Null
    $target = Join-Path $TextfileDir $FileName
    $tmp = "$target.tmp"
    [System.IO.File]::WriteAllText($tmp, $Body, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $target -Force
}

if (-not $env:RESTIC_REPOSITORY) { throw 'RESTIC_REPOSITORY is not set' }
if (-not $env:RESTIC_PASSWORD_FILE -and -not $env:RESTIC_PASSWORD) {
    throw 'Set RESTIC_PASSWORD_FILE (preferred) or RESTIC_PASSWORD'
}

$hostName = $env:COMPUTERNAME.ToLowerInvariant()
$stateDir = 'C:\ProgramData\backup'
$expectedFile = Join-Path $stateDir 'canary.sha256'
if (-not (Test-Path -LiteralPath $expectedFile)) {
    throw "Canary hash not found at $expectedFile; run backup.ps1 first"
}
$expectedHash = ((Get-Content -LiteralPath $expectedFile -TotalCount 1) -split '\s+')[0]
$canarySource = (Get-Content -LiteralPath $expectedFile -TotalCount 1) -replace '^\S+\s+', ''

$target = Join-Path ([System.IO.Path]::GetTempPath()) ("restore-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $target | Out-Null
try {
    & restic restore latest --tag $Job --host $hostName --target $target --include $canarySource
    if ($LASTEXITCODE -ne 0) { throw "restic restore failed with exit code $LASTEXITCODE" }

    $restored = Get-ChildItem -LiteralPath $target -Recurse -File -Filter 'restore-canary.txt' | Select-Object -First 1
    if (-not $restored) { throw 'Canary file not present in restored output' }

    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $restored.FullName).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Canary hash mismatch: expected $expectedHash, got $actualHash"
    }
}
finally {
    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
}

$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body = @(
    '# HELP backup_last_restore_test_timestamp_seconds Unix time of the last successful restore test (canary hash verified).'
    '# TYPE backup_last_restore_test_timestamp_seconds gauge'
    "backup_last_restore_test_timestamp_seconds{job=""$Job"",host=""$hostName""} $now"
) -join "`n"
Write-TextfileMetric -FileName 'backup_restore_test.prom' -Body ($body + "`n")
Write-Host 'Restore test passed; metric updated.'
