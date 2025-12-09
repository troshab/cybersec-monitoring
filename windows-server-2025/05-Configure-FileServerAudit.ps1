<#
.SYNOPSIS
    Налаштування аудиту доступу до файлів на File Server.

.DESCRIPTION
    Активує детальний аудит файлового сервера:
    - Object Access auditing
    - File Share auditing
    - Removable Storage auditing
    - SACL на критичних шарах

.PARAMETER SharePaths
    Масив шляхів до шар для налаштування аудиту

.EXAMPLE
    .\05-Configure-FileServerAudit.ps1

.EXAMPLE
    .\05-Configure-FileServerAudit.ps1 -SharePaths @("D:\Share1", "E:\Data")

.NOTES
    Запускати на File Server
    Аудит може збільшити об'єм логів
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string[]]$SharePaths
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

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  File Server Audit Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Налаштування Audit Policy
# =============================================================================
Write-Log "Налаштування Object Access Audit Policy..." -Level Info

$fileAuditPolicies = @(
    @{SubCategory = "File System"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "File Share"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Detailed File Share"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Removable Storage"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Handle Manipulation"; Success = "enable"; Failure = "disable"},
    @{SubCategory = "Central Policy Staging"; Success = "enable"; Failure = "enable"}
)

foreach ($policy in $fileAuditPolicies) {
    $result = auditpol /set /subcategory:"$($policy.SubCategory)" /success:$($policy.Success) /failure:$($policy.Failure) 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Налаштовано: $($policy.SubCategory)" -Level Success
    } else {
        Write-Log "Error: $($policy.SubCategory)" -Level Warning
    }
}

# =============================================================================
# Пошук існуючих шар
# =============================================================================
Write-Log "Пошук мережевих шар..." -Level Info

if (-not $SharePaths) {
    # Автоматичний пошук всіх не-системних шар
    $shares = Get-SmbShare | Where-Object {
        $_.Name -notmatch '^\$' -and
        $_.Path -and
        $_.ShareType -eq 'FileSystemDirectory'
    }

    $SharePaths = $shares | Select-Object -ExpandProperty Path
}

if ($SharePaths.Count -eq 0) {
    Write-Log "Мережеві шари не знайдено" -Level Warning
} else {
    Write-Log "Знайдено шар: $($SharePaths.Count)" -Level Success
    foreach ($path in $SharePaths) {
        Write-Log "  - $path" -Level Info
    }
}

# =============================================================================
# Налаштування SACL на шарах
# =============================================================================
function Set-FileAuditRule {
    param(
        [string]$Path,
        [string]$Identity = "Everyone",
        [System.Security.AccessControl.FileSystemRights]$Rights = "FullControl",
        [System.Security.AccessControl.AuditFlags]$AuditFlags = "Success, Failure"
    )

    try {
        if (-not (Test-Path $Path)) {
            Write-Log "Шлях не існує: $Path" -Level Warning
            return
        }

        $acl = Get-Acl -Path $Path -Audit

        # Audit rule для всіх (Success and Failure)
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $Identity,
            $Rights,
            "ContainerInherit,ObjectInherit",
            "None",
            $AuditFlags
        )

        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $Path -AclObject $acl

        Write-Log "SACL налаштовано: $Path" -Level Success

    } catch {
        Write-Log "Помилка SACL для $Path`: $_" -Level Error
    }
}

Write-Log "Налаштування SACL на мережевих шарах..." -Level Info

foreach ($sharePath in $SharePaths) {
    if (Test-Path $sharePath) {
        # Базовий аудит
        Set-FileAuditRule -Path $sharePath -Identity "Everyone" -Rights "Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership, Write" -AuditFlags "Success, Failure"
    }
}

# =============================================================================
# Налаштування Global Object Access Auditing (через GPO)
# =============================================================================
Write-Log "Налаштування Global Object Access Auditing..." -Level Info

# Це вимагає налаштування через Group Policy
# Computer Configuration > Windows Settings > Security Settings >
# Advanced Audit Policy Configuration > Global Object Access Auditing

$goaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $goaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force

Write-Log "Legacy Audit Policy вимкнено (використовується Advanced)" -Level Success

# =============================================================================
# Розмір Security Log
# =============================================================================
Write-Log "Налаштування Security Event Log для File Server..." -Level Info

try {
    # Збільшення до 512 MB для file server (багато подій)
    wevtutil sl Security /ms:536870912

    Write-Log "Security Log: 512 MB" -Level Success
} catch {
    Write-Log "Помилка налаштування Security Log" -Level Warning
}

# =============================================================================
# SMB Server Audit
# =============================================================================
Write-Log "Configuring SMB Server Audit..." -Level Info

try {
    # Увімкнення SMB аудиту
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force

    Write-Log "SMB1 Access Audit увімкнено" -Level Success
} catch {
    Write-Log "Помилка SMB Audit: $_" -Level Warning
}

# =============================================================================
# File Server Resource Manager (FSRM) - якщо встановлено
# =============================================================================
$fsrmFeature = Get-WindowsFeature -Name FS-Resource-Manager -ErrorAction SilentlyContinue
if ($fsrmFeature -and $fsrmFeature.Installed) {
    Write-Log "Налаштування FSRM..." -Level Info

    try {
        Import-Module FileServerResourceManager -ErrorAction Stop

        # Налаштування email notifications
        # Set-FsrmSetting -SmtpServer "smtp.company.local" -AdminEmailAddress "admin@company.local"

        Write-Log "FSRM доступний для налаштування" -Level Success
    } catch {
        Write-Log "FSRM модуль недоступний" -Level Warning
    }
} else {
    Write-Log "FSRM не встановлено (optional)" -Level Info
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  File Server Audit Configuration Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Налаштовані шари:" -ForegroundColor Cyan
foreach ($path in $SharePaths) {
    Write-Host "  [+] $path"
}
Write-Host ""
Write-Host "Важливі File Server Event IDs:" -ForegroundColor Yellow
Write-Host ""
Write-Host "File Access (Security Log):" -ForegroundColor Cyan
Write-Host "  4656 - Handle to an object was requested"
Write-Host "  4658 - Handle to an object was closed"
Write-Host "  4660 - Object was deleted"
Write-Host "  4663 - Access attempt to object"
Write-Host "  4670 - Permissions on object changed"
Write-Host ""
Write-Host "File Share Access:" -ForegroundColor Cyan
Write-Host "  5140 - Network share object accessed"
Write-Host "  5142 - Network share object added"
Write-Host "  5143 - Network share object modified"
Write-Host "  5144 - Network share object deleted"
Write-Host "  5145 - Network share access check (detailed)"
Write-Host ""
Write-Host "Ransomware Detection Events:" -ForegroundColor Red
Write-Host "  4663 + масове видалення/зміна файлів"
Write-Host "  Підозрілі розширення: .encrypted, .locked, .crypto"
Write-Host ""
Write-Host "Loki запити для File Server:" -ForegroundColor Yellow
Write-Host '  # Доступ до файлів'
Write-Host '  {job="windows_security"} |= "4663"'
Write-Host ""
Write-Host '  # Видалення файлів'
Write-Host '  {job="windows_security"} |= "4660"'
Write-Host ""
Write-Host '  # Мережевий доступ до шар'
Write-Host '  {job="windows_security"} |= "5140"'
Write-Host ""
Write-Host "УВАГА:" -ForegroundColor Yellow
Write-Host "  - File audit генерує ДУЖЕ багато подій"
Write-Host "  - Рекомендується аудит тільки критичних операцій"
Write-Host "  - Налаштуйте фільтри в Promtail"
Write-Host ""
