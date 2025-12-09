<#
.SYNOPSIS
    Configure Windows audit policies for collecting critical security events.

.DESCRIPTION
    This script configures advanced Windows auditing to collect all critical
    security events, including logins, account changes, process execution, etc.

    Налаштовує:
    - Advanced Audit Policy
    - Command line logging для процесів
    - Розміри Event Log

.PARAMETER BackupPath
    Path to save backup of current settings

.EXAMPLE
    .\01-Set-AuditPolicy.ps1
    Applies recommended audit settings

.EXAMPLE
    .\01-Set-AuditPolicy.ps1 -BackupPath "C:\Backup"
    Saves backup before applying

.NOTES
    Requires administrator rights
    Event IDs that will be generated: 4624, 4625, 4720, 4732, 4688, 4697, 7045 and others

.LINK
    https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$BackupPath = "$env:TEMP\AuditPolicyBackup"
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Functions
# =============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $colors = @{
        'Info'    = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }

    $prefix = @{
        'Info'    = '[*]'
        'Success' = '[+]'
        'Warning' = '[!]'
        'Error'   = '[-]'
    }

    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Backup-AuditPolicy {
    param([string]$Path)

    Write-Log "Creating backup of current settings..." -Level Info

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $backupFile = Join-Path $Path "auditpol_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    auditpol /backup /file:$backupFile

    Write-Log "Backup saved: $backupFile" -Level Success
}

function Set-AuditSubcategory {
    param(
        [string]$Subcategory,
        [ValidateSet('Success', 'Failure', 'Both', 'None')]
        [string]$Setting
    )

    $settingMap = @{
        'Success' = '/success:enable /failure:disable'
        'Failure' = '/success:disable /failure:enable'
        'Both'    = '/success:enable /failure:enable'
        'None'    = '/success:disable /failure:disable'
    }

    $cmd = "auditpol /set /subcategory:`"$Subcategory`" $($settingMap[$Setting])"
    Invoke-Expression $cmd 2>&1 | Out-Null
}

# =============================================================================
# Main Script
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Windows Audit Policy Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Backup
if ($BackupPath) {
    Backup-AuditPolicy -Path $BackupPath
}

# -----------------------------------------------------------------------------
# Account Logon
# -----------------------------------------------------------------------------
Write-Log "Configuring Account Logon..." -Level Info

Set-AuditSubcategory -Subcategory "Credential Validation" -Setting Both
Set-AuditSubcategory -Subcategory "Kerberos Authentication Service" -Setting Both
Set-AuditSubcategory -Subcategory "Kerberos Service Ticket Operations" -Setting Both

# -----------------------------------------------------------------------------
# Account Management
# -----------------------------------------------------------------------------
Write-Log "Configuring Account Management..." -Level Info

Set-AuditSubcategory -Subcategory "Computer Account Management" -Setting Both
Set-AuditSubcategory -Subcategory "Security Group Management" -Setting Both
Set-AuditSubcategory -Subcategory "User Account Management" -Setting Both
Set-AuditSubcategory -Subcategory "Distribution Group Management" -Setting Both

# -----------------------------------------------------------------------------
# Detailed Tracking
# -----------------------------------------------------------------------------
Write-Log "Configuring Detailed Tracking..." -Level Info

Set-AuditSubcategory -Subcategory "Process Creation" -Setting Success
Set-AuditSubcategory -Subcategory "Process Termination" -Setting Success
Set-AuditSubcategory -Subcategory "Plug and Play Events" -Setting Success

# -----------------------------------------------------------------------------
# Logon/Logoff
# -----------------------------------------------------------------------------
Write-Log "Configuring Logon/Logoff..." -Level Info

Set-AuditSubcategory -Subcategory "Account Lockout" -Setting Both
Set-AuditSubcategory -Subcategory "Logoff" -Setting Success
Set-AuditSubcategory -Subcategory "Logon" -Setting Both
Set-AuditSubcategory -Subcategory "Special Logon" -Setting Success
Set-AuditSubcategory -Subcategory "Other Logon/Logoff Events" -Setting Both

# -----------------------------------------------------------------------------
# Object Access
# -----------------------------------------------------------------------------
Write-Log "Configuring Object Access..." -Level Info

Set-AuditSubcategory -Subcategory "File System" -Setting Failure
Set-AuditSubcategory -Subcategory "Registry" -Setting Failure
Set-AuditSubcategory -Subcategory "Kernel Object" -Setting Failure
Set-AuditSubcategory -Subcategory "SAM" -Setting Failure
Set-AuditSubcategory -Subcategory "Removable Storage" -Setting Both
Set-AuditSubcategory -Subcategory "File Share" -Setting Both
Set-AuditSubcategory -Subcategory "Detailed File Share" -Setting Failure

# -----------------------------------------------------------------------------
# Policy Change
# -----------------------------------------------------------------------------
Write-Log "Configuring Policy Change..." -Level Info

Set-AuditSubcategory -Subcategory "Audit Policy Change" -Setting Both
Set-AuditSubcategory -Subcategory "Authentication Policy Change" -Setting Success
Set-AuditSubcategory -Subcategory "Authorization Policy Change" -Setting Both
Set-AuditSubcategory -Subcategory "MPSSVC Rule-Level Policy Change" -Setting Both

# -----------------------------------------------------------------------------
# Privilege Use
# -----------------------------------------------------------------------------
Write-Log "Configuring Privilege Use..." -Level Info

Set-AuditSubcategory -Subcategory "Sensitive Privilege Use" -Setting Both
Set-AuditSubcategory -Subcategory "Non Sensitive Privilege Use" -Setting Failure

# -----------------------------------------------------------------------------
# System
# -----------------------------------------------------------------------------
Write-Log "Configuring System..." -Level Info

Set-AuditSubcategory -Subcategory "Security State Change" -Setting Both
Set-AuditSubcategory -Subcategory "Security System Extension" -Setting Both
Set-AuditSubcategory -Subcategory "System Integrity" -Setting Both
Set-AuditSubcategory -Subcategory "Other System Events" -Setting Both

# -----------------------------------------------------------------------------
# Command Line in Process Creation Events
# -----------------------------------------------------------------------------
Write-Log "Enabling Command Line logging..." -Level Info

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# Event Log Sizes
# -----------------------------------------------------------------------------
Write-Log "Configuring Event Log sizes..." -Level Info

# Security Log: 1GB
wevtutil sl Security /ms:1073741824

# System Log: 256MB
wevtutil sl System /ms:268435456

# Application Log: 256MB
wevtutil sl Application /ms:268435456

# PowerShell Operational: 256MB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456

# Sysmon (if exists)
try {
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456 2>$null
} catch {}

Write-Log "Log sizes configured" -Level Success

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
Write-Host ""
Write-Log "Verifying settings..." -Level Info
Write-Host ""

# Показати поточні налаштування
Write-Host "Current audit configuration:" -ForegroundColor Yellow
auditpol /get /category:*

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Audit configuration completed successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Run 02-Enable-PowerShellLogging.ps1"
Write-Host "  2. Run 03-Install-Sysmon.ps1"
Write-Host "  3. Check Event Viewer -> Security Log"
Write-Host ""
