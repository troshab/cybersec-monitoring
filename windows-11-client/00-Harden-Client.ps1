<#
.SYNOPSIS
    Central hardening script for Windows 11 client.

.DESCRIPTION
    Master script that executes all hardening and security configuration:
    - Audit policy (from windows-common)
    - PowerShell logging (from windows-common)
    - Telemetry disable (optional)
    - Security hardening (SMB, firewall, PtH protection, etc.)

.PARAMETER SkipTelemetry
    Skip telemetry disabling

.PARAMETER SkipFirewall
    Skip firewall configuration

.PARAMETER SkipSMB
    Skip SMB hardening

.EXAMPLE
    .\00-Harden-Client.ps1

.EXAMPLE
    .\00-Harden-Client.ps1 -SkipTelemetry

.NOTES
    Run as administrator
    Reboot recommended after completion
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipTelemetry,
    [switch]$SkipFirewall,
    [switch]$SkipSMB
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    $colors = @{ 'Info' = 'Cyan'; 'Success' = 'Green'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $prefix = @{ 'Info' = '[*]'; 'Success' = '[+]'; 'Warning' = '[!]'; 'Error' = '[-]' }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Run-Script {
    param(
        [string]$ScriptPath,
        [string]$Description,
        [hashtable]$Parameters = @{}
    )

    if (Test-Path $ScriptPath) {
        Write-Log "Running: $Description" -Level Info
        try {
            & $ScriptPath @Parameters
            Write-Log "Completed: $Description" -Level Success
            return $true
        } catch {
            Write-Log "Error in $Description`: $_" -Level Error
            return $false
        }
    } else {
        Write-Log "Not found: $ScriptPath" -Level Warning
        return $false
    }
}

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CommonDir = Join-Path (Split-Path -Parent $ScriptDir) "windows-common"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Client - Central Hardening Script" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will apply:" -ForegroundColor White
Write-Host "  1. Audit Policy configuration" -ForegroundColor Gray
Write-Host "  2. PowerShell logging" -ForegroundColor Gray
Write-Host "  3. Telemetry disable (if not skipped)" -ForegroundColor Gray
Write-Host "  4. Security hardening (firewall, SMB, PtH, etc.)" -ForegroundColor Gray
Write-Host ""

$results = @()

# =============================================================================
# Step 1: Audit Policy
# =============================================================================
Write-Host ""
Write-Host "=== Step 1/4: Audit Policy ===" -ForegroundColor Yellow
$auditScript = Join-Path $CommonDir "01-Set-AuditPolicy.ps1"
$results += @{Step = "Audit Policy"; Success = (Run-Script -ScriptPath $auditScript -Description "Audit Policy configuration")}

# =============================================================================
# Step 2: PowerShell Logging
# =============================================================================
Write-Host ""
Write-Host "=== Step 2/4: PowerShell Logging ===" -ForegroundColor Yellow
$psScript = Join-Path $CommonDir "02-Enable-PowerShellLogging.ps1"
$results += @{Step = "PowerShell Logging"; Success = (Run-Script -ScriptPath $psScript -Description "PowerShell logging configuration")}

# =============================================================================
# Step 3: Telemetry (Optional)
# =============================================================================
Write-Host ""
Write-Host "=== Step 3/4: Telemetry ===" -ForegroundColor Yellow
if (-not $SkipTelemetry) {
    $telemetryScript = Join-Path $ScriptDir "01-Disable-Telemetry.ps1"
    $results += @{Step = "Telemetry"; Success = (Run-Script -ScriptPath $telemetryScript -Description "Telemetry disable")}
} else {
    Write-Log "Telemetry configuration skipped (-SkipTelemetry)" -Level Warning
    $results += @{Step = "Telemetry"; Success = $true}
}

# =============================================================================
# Step 4: Security Hardening
# =============================================================================
Write-Host ""
Write-Host "=== Step 4/4: Security Hardening ===" -ForegroundColor Yellow
$hardenScript = Join-Path $ScriptDir "02-Harden-Client.ps1"
$hardenParams = @{}
if ($SkipFirewall) { $hardenParams['SkipFirewall'] = $true }
if ($SkipSMB) { $hardenParams['SkipSMB'] = $true }
$results += @{Step = "Security Hardening"; Success = (Run-Script -ScriptPath $hardenScript -Description "Security hardening" -Parameters $hardenParams)}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Windows 11 Hardening Summary" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

$successCount = ($results | Where-Object { $_.Success }).Count
$totalCount = $results.Count

foreach ($result in $results) {
    $status = if ($result.Success) { "[OK]" } else { "[FAIL]" }
    $color = if ($result.Success) { "Green" } else { "Red" }
    Write-Host "  $status $($result.Step)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Result: $successCount/$totalCount steps completed successfully" -ForegroundColor $(if ($successCount -eq $totalCount) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - Reboot recommended to apply all changes" -ForegroundColor White
Write-Host "  - Check application functionality after reboot" -ForegroundColor White
Write-Host ""
