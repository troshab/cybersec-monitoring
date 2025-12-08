<#
.SYNOPSIS
    Налаштування політик аудиту Windows для збору критичних подій безпеки.

.DESCRIPTION
    Цей скрипт налаштовує розширений аудит Windows для збору всіх критичних
    подій безпеки, включаючи входи, зміни облікових записів, запуск процесів тощо.

    Налаштовує:
    - Advanced Audit Policy
    - Command line logging для процесів
    - Розміри Event Log

.PARAMETER BackupPath
    Шлях для збереження backup поточних налаштувань

.EXAMPLE
    .\01-Set-AuditPolicy.ps1
    Застосовує рекомендовані налаштування аудиту

.EXAMPLE
    .\01-Set-AuditPolicy.ps1 -BackupPath "C:\Backup"
    Зберігає backup перед застосуванням

.NOTES
    Вимагає прав адміністратора
    Event IDs що будуть генеруватись: 4624, 4625, 4720, 4732, 4688, 4697, 7045 та інші

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

    Write-Log "Створення backup поточних налаштувань..." -Level Info

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $backupFile = Join-Path $Path "auditpol_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    auditpol /backup /file:$backupFile

    Write-Log "Backup збережено: $backupFile" -Level Success
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
Write-Log "Налаштування Account Logon..." -Level Info

Set-AuditSubcategory -Subcategory "Credential Validation" -Setting Both
Set-AuditSubcategory -Subcategory "Kerberos Authentication Service" -Setting Both
Set-AuditSubcategory -Subcategory "Kerberos Service Ticket Operations" -Setting Both

# -----------------------------------------------------------------------------
# Account Management
# -----------------------------------------------------------------------------
Write-Log "Налаштування Account Management..." -Level Info

Set-AuditSubcategory -Subcategory "Computer Account Management" -Setting Both
Set-AuditSubcategory -Subcategory "Security Group Management" -Setting Both
Set-AuditSubcategory -Subcategory "User Account Management" -Setting Both
Set-AuditSubcategory -Subcategory "Distribution Group Management" -Setting Both

# -----------------------------------------------------------------------------
# Detailed Tracking
# -----------------------------------------------------------------------------
Write-Log "Налаштування Detailed Tracking..." -Level Info

Set-AuditSubcategory -Subcategory "Process Creation" -Setting Success
Set-AuditSubcategory -Subcategory "Process Termination" -Setting Success
Set-AuditSubcategory -Subcategory "Plug and Play Events" -Setting Success

# -----------------------------------------------------------------------------
# Logon/Logoff
# -----------------------------------------------------------------------------
Write-Log "Налаштування Logon/Logoff..." -Level Info

Set-AuditSubcategory -Subcategory "Account Lockout" -Setting Both
Set-AuditSubcategory -Subcategory "Logoff" -Setting Success
Set-AuditSubcategory -Subcategory "Logon" -Setting Both
Set-AuditSubcategory -Subcategory "Special Logon" -Setting Success
Set-AuditSubcategory -Subcategory "Other Logon/Logoff Events" -Setting Both

# -----------------------------------------------------------------------------
# Object Access
# -----------------------------------------------------------------------------
Write-Log "Налаштування Object Access..." -Level Info

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
Write-Log "Налаштування Policy Change..." -Level Info

Set-AuditSubcategory -Subcategory "Audit Policy Change" -Setting Both
Set-AuditSubcategory -Subcategory "Authentication Policy Change" -Setting Success
Set-AuditSubcategory -Subcategory "Authorization Policy Change" -Setting Both
Set-AuditSubcategory -Subcategory "MPSSVC Rule-Level Policy Change" -Setting Both

# -----------------------------------------------------------------------------
# Privilege Use
# -----------------------------------------------------------------------------
Write-Log "Налаштування Privilege Use..." -Level Info

Set-AuditSubcategory -Subcategory "Sensitive Privilege Use" -Setting Both
Set-AuditSubcategory -Subcategory "Non Sensitive Privilege Use" -Setting Failure

# -----------------------------------------------------------------------------
# System
# -----------------------------------------------------------------------------
Write-Log "Налаштування System..." -Level Info

Set-AuditSubcategory -Subcategory "Security State Change" -Setting Both
Set-AuditSubcategory -Subcategory "Security System Extension" -Setting Both
Set-AuditSubcategory -Subcategory "System Integrity" -Setting Both
Set-AuditSubcategory -Subcategory "Other System Events" -Setting Both

# -----------------------------------------------------------------------------
# Command Line in Process Creation Events
# -----------------------------------------------------------------------------
Write-Log "Включення Command Line logging..." -Level Info

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# Event Log Sizes
# -----------------------------------------------------------------------------
Write-Log "Налаштування розмірів Event Log..." -Level Info

# Security Log: 1GB
wevtutil sl Security /ms:1073741824

# System Log: 256MB
wevtutil sl System /ms:268435456

# Application Log: 256MB
wevtutil sl Application /ms:268435456

# PowerShell Operational: 256MB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456

# Sysmon (якщо існує)
try {
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456 2>$null
} catch {}

Write-Log "Розміри логів налаштовано" -Level Success

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
Write-Host ""
Write-Log "Перевірка налаштувань..." -Level Info
Write-Host ""

# Показати поточні налаштування
Write-Host "Поточна конфігурація аудиту:" -ForegroundColor Yellow
auditpol /get /category:*

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Налаштування аудиту завершено успішно!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Що далі:" -ForegroundColor Cyan
Write-Host "  1. Запустіть 02-Enable-PowerShellLogging.ps1"
Write-Host "  2. Запустіть 03-Install-Sysmon.ps1"
Write-Host "  3. Перевірте Event Viewer → Security Log"
Write-Host ""
