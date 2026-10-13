# =============================================================================
# Backup (restic) for Windows endpoints/servers
# =============================================================================
# CIS IG1 11.2 - Perform automated backups (metrics: backup_last_success_timestamp_seconds)
# CIS IG1 11.4 - Protect backup data: the restic repository is encrypted; the
#                password is never stored in this repository.
#
# Requires: restic 0.19.1 on PATH (https://github.com/restic/restic/releases/tag/v0.19.1)
# Environment (set outside the repo, e.g. machine env vars or a file under
# C:\ProgramData\backup\restic.env that is ACL-restricted to SYSTEM/Administrators):
#   RESTIC_REPOSITORY       repository URL or path
#   RESTIC_PASSWORD_FILE    path to a file holding the repo password
#   RESTIC_APPEND_ONLY      1 = append-only repository on the server (same as -AppendOnly)
#
# Usage:
#   .\backup.ps1 -Paths 'C:\Data','C:\Shares' -DryRun
#   .\backup.ps1 -Paths 'C:\Data'
#
# The success timestamp is written only after backup, forget/prune (skipped with
# -AppendOnly or RESTIC_APPEND_ONLY=1) and a partial data check
# (restic check --read-data-subset=5%) have all succeeded.
# =============================================================================

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,

    [switch]$DryRun,

    [string]$TextfileDir = 'C:\Program Files\windows_exporter\textfile_inputs',

    [string]$Job = 'restic',

    [switch]$AppendOnly
)

$appendOnly = $AppendOnly -or ($env:RESTIC_APPEND_ONLY -eq '1')

$ErrorActionPreference = 'Stop'

function Invoke-Restic {
    param([string[]]$Arguments)
    & restic @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "restic $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
}

function Write-TextfileMetric {
    # Atomic write: the exporter never sees a partially written .prom file.
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

# Canary: a random token inside the backup set. restore-test.ps1 restores it and
# compares its hash with the value stored outside the repository.
$stateDir = 'C:\ProgramData\backup'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$canaryDir = Join-Path $stateDir 'canary'
New-Item -ItemType Directory -Force -Path $canaryDir | Out-Null
$canaryFile = Join-Path $canaryDir 'restore-canary.txt'
if (-not $DryRun) {
    $token = [guid]::NewGuid().ToString('N')
    [System.IO.File]::WriteAllText($canaryFile, "$token`n", (New-Object System.Text.UTF8Encoding($false)))
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $canaryFile).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $stateDir 'canary.sha256'), "$hash  $canaryFile`n")
}

$backupArgs = @('backup', '--tag', $Job, '--host', $hostName) + $Paths
if ($DryRun) { $backupArgs += '--dry-run' } else { $backupArgs += $canaryFile }
Invoke-Restic -Arguments $backupArgs

if ($DryRun) {
    Write-Host 'Dry run complete; no retention, check or metric update performed.'
    exit 0
}

if ($appendOnly) {
    Write-Host 'AppendOnly: forget/prune skipped; prune runs on the server with separate credentials.'
} else {
    Invoke-Restic -Arguments @('forget', '--tag', $Job, '--host', $hostName,
        '--keep-daily', '7', '--keep-weekly', '4', '--keep-monthly', '6', '--prune')
}
Invoke-Restic -Arguments @('check', '--read-data-subset=5%')

$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body = @(
    '# HELP backup_last_success_timestamp_seconds Unix time of the last successful backup run (forget and check included).'
    '# TYPE backup_last_success_timestamp_seconds gauge'
    "backup_last_success_timestamp_seconds{job=""$Job"",host=""$hostName""} $now"
) -join "`n"
Write-TextfileMetric -FileName 'backup_last_success.prom' -Body ($body + "`n")
Write-Host "Backup completed; metric written to $TextfileDir\backup_last_success.prom"
