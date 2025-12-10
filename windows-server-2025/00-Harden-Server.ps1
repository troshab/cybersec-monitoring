<#
.SYNOPSIS
    Central hardening script for Windows Server 2025.

.DESCRIPTION
    Master script that executes all hardening and security configuration:
    - Audit policy (from windows-common)
    - PowerShell logging (from windows-common)
    - Server hardening (SMB, TLS, firewall, PtH protection, etc.)
    - Active Directory auditing (if DC role present)
    - DHCP/DNS/NPS logging (if roles present)

.PARAMETER SkipFirewall
    Skip firewall configuration

.PARAMETER SkipTLS
    Skip TLS/SSL hardening

.PARAMETER SkipRoleConfig
    Skip role-specific configuration (AD, DHCP, DNS, NPS, File Server)

.EXAMPLE
    .\00-Harden-Server.ps1

.EXAMPLE
    .\00-Harden-Server.ps1 -SkipRoleConfig

.NOTES
    Run as administrator
    Reboot recommended after completion
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipFirewall,
    [switch]$SkipTLS,
    [switch]$SkipRoleConfig
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

function Test-ServerRole {
    param([string]$RoleName)

    try {
        $feature = Get-WindowsFeature -Name $RoleName -ErrorAction SilentlyContinue
        return ($feature -and $feature.Installed)
    } catch {
        return $false
    }
}

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CommonDir = Join-Path (Split-Path -Parent $ScriptDir) "windows-common"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Windows Server 2025 - Central Hardening Script" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Detect installed roles
Write-Host "Detecting installed roles..." -ForegroundColor White
$isDC = Test-ServerRole "AD-Domain-Services"
$isDHCP = Test-ServerRole "DHCP"
$isDNS = Test-ServerRole "DNS"
$isNPS = Test-ServerRole "NPAS"
$isFileServer = Test-ServerRole "FS-FileServer"

Write-Host "  Domain Controller: $(if($isDC){'Yes'}else{'No'})" -ForegroundColor Gray
Write-Host "  DHCP Server: $(if($isDHCP){'Yes'}else{'No'})" -ForegroundColor Gray
Write-Host "  DNS Server: $(if($isDNS){'Yes'}else{'No'})" -ForegroundColor Gray
Write-Host "  NPS (RADIUS): $(if($isNPS){'Yes'}else{'No'})" -ForegroundColor Gray
Write-Host "  File Server: $(if($isFileServer){'Yes'}else{'No'})" -ForegroundColor Gray
Write-Host ""

Write-Host "This script will apply:" -ForegroundColor White
Write-Host "  1. Audit Policy configuration" -ForegroundColor Gray
Write-Host "  2. PowerShell logging" -ForegroundColor Gray
Write-Host "  3. Server security hardening" -ForegroundColor Gray
if (-not $SkipRoleConfig) {
    Write-Host "  4. Role-specific configurations (if roles detected)" -ForegroundColor Gray
}
Write-Host ""

$results = @()

# =============================================================================
# Step 1: Audit Policy
# =============================================================================
Write-Host ""
Write-Host "=== Step 1: Audit Policy ===" -ForegroundColor Yellow
$auditScript = Join-Path $CommonDir "01-Set-AuditPolicy.ps1"
$results += @{Step = "Audit Policy"; Success = (Run-Script -ScriptPath $auditScript -Description "Audit Policy configuration")}

# =============================================================================
# Step 2: PowerShell Logging
# =============================================================================
Write-Host ""
Write-Host "=== Step 2: PowerShell Logging ===" -ForegroundColor Yellow
$psScript = Join-Path $CommonDir "02-Enable-PowerShellLogging.ps1"
$results += @{Step = "PowerShell Logging"; Success = (Run-Script -ScriptPath $psScript -Description "PowerShell logging configuration")}

# =============================================================================
# Step 3: Server Security Hardening
# =============================================================================
Write-Host ""
Write-Host "=== Step 3: Server Security Hardening ===" -ForegroundColor Yellow
$hardenScript = Join-Path $ScriptDir "01-Harden-Server.ps1"
$hardenParams = @{}
if ($SkipFirewall) { $hardenParams['SkipFirewall'] = $true }
if ($SkipTLS) { $hardenParams['SkipTLS'] = $true }
$results += @{Step = "Server Hardening"; Success = (Run-Script -ScriptPath $hardenScript -Description "Server security hardening" -Parameters $hardenParams)}

# =============================================================================
# Step 4: Role-Specific Configurations
# =============================================================================
if (-not $SkipRoleConfig) {
    Write-Host ""
    Write-Host "=== Step 4: Role-Specific Configurations ===" -ForegroundColor Yellow

    # Active Directory
    if ($isDC) {
        $adScript = Join-Path $ScriptDir "02-Configure-ADDSAudit.ps1"
        $results += @{Step = "AD DS Audit"; Success = (Run-Script -ScriptPath $adScript -Description "Active Directory auditing")}
    }

    # DHCP
    if ($isDHCP) {
        $dhcpScript = Join-Path $ScriptDir "03-Configure-DHCPLogging.ps1"
        $results += @{Step = "DHCP Logging"; Success = (Run-Script -ScriptPath $dhcpScript -Description "DHCP logging configuration")}
    }

    # DNS
    if ($isDNS) {
        $dnsScript = Join-Path $ScriptDir "04-Configure-DNSLogging.ps1"
        $results += @{Step = "DNS Logging"; Success = (Run-Script -ScriptPath $dnsScript -Description "DNS logging configuration")}
    }

    # File Server
    if ($isFileServer) {
        $fsScript = Join-Path $ScriptDir "05-Configure-FileServerAudit.ps1"
        $results += @{Step = "File Server Audit"; Success = (Run-Script -ScriptPath $fsScript -Description "File Server auditing")}
    }

    # NPS
    if ($isNPS) {
        $npsScript = Join-Path $ScriptDir "06-Configure-NPSLogging.ps1"
        $results += @{Step = "NPS Logging"; Success = (Run-Script -ScriptPath $npsScript -Description "NPS logging configuration")}
    }

    if (-not ($isDC -or $isDHCP -or $isDNS -or $isFileServer -or $isNPS)) {
        Write-Log "No specific roles detected - skipping role configuration" -Level Info
    }
} else {
    Write-Log "Role-specific configuration skipped (-SkipRoleConfig)" -Level Warning
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Windows Server 2025 Hardening Summary" -ForegroundColor Green
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
Write-Host "  - TLS changes may affect legacy clients" -ForegroundColor White
Write-Host "  - Verify services functionality after reboot" -ForegroundColor White
Write-Host ""
