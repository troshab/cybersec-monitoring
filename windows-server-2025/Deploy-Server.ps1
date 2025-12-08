<#
.SYNOPSIS
    Головний скрипт розгортання моніторингу на Windows Server 2025.

.DESCRIPTION
    Автоматично виконує всі кроки налаштування сервера:
    1. Базовий Audit Policy
    2. PowerShell Logging
    3. Sysmon
    4. Promtail
    5. Windows Exporter
    6. Server Hardening
    7. Role-specific logging (ADDS, DHCP, DNS, File Server, NPS)
    8. Osquery (опціонально)

.PARAMETER LokiUrl
    URL сервера Loki (обов'язковий)

.PARAMETER FleetUrl
    URL FleetDM сервера (опціонально)

.PARAMETER FleetEnrollSecret
    Секрет для FleetDM (опціонально)

.PARAMETER SkipSysmon
    Пропустити встановлення Sysmon

.PARAMETER SkipOsquery
    Пропустити встановлення osquery

.PARAMETER SkipHardening
    Пропустити hardening (для тестових середовищ)

.PARAMETER ServerRoles
    Ролі сервера для налаштування (ADDS, DHCP, DNS, FileServer, NPS)

.EXAMPLE
    .\Deploy-Server.ps1 -LokiUrl "http://192.168.1.100:3100"

.EXAMPLE
    .\Deploy-Server.ps1 -LokiUrl "http://loki:3100" -ServerRoles "ADDS","DNS","DHCP"

.EXAMPLE
    .\Deploy-Server.ps1 -LokiUrl "http://loki:3100" -FleetUrl "https://fleet:8080" -FleetEnrollSecret "secret"

.NOTES
    Запускати від адміністратора
    Час виконання: ~10-20 хвилин залежно від ролей
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LokiUrl,

    [string]$FleetUrl,

    [string]$FleetEnrollSecret,

    [switch]$SkipSysmon,

    [switch]$SkipOsquery,

    [switch]$SkipHardening,

    [ValidateSet("ADDS", "DHCP", "DNS", "FileServer", "NPS")]
    [string[]]$ServerRoles
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CommonDir = Join-Path (Split-Path -Parent $ScriptDir) "windows-common"

function Write-Log {
    param([string]$Message, [string]$Level = 'Info')
    $colors = @{ 'Info' = 'Cyan'; 'Success' = 'Green'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $prefix = @{ 'Info' = '[*]'; 'Success' = '[+]'; 'Warning' = '[!]'; 'Error' = '[-]' }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Write-Banner {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

# =============================================================================
# Auto-detect Server Roles
# =============================================================================
function Get-InstalledServerRoles {
    $detectedRoles = @()

    # ADDS
    if (Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue | Where-Object { $_.Installed }) {
        $detectedRoles += "ADDS"
    }

    # DHCP
    if (Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue | Where-Object { $_.Installed }) {
        $detectedRoles += "DHCP"
    }

    # DNS
    if (Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue | Where-Object { $_.Installed }) {
        $detectedRoles += "DNS"
    }

    # File Server
    if (Get-WindowsFeature -Name FS-FileServer -ErrorAction SilentlyContinue | Where-Object { $_.Installed }) {
        $detectedRoles += "FileServer"
    }

    # NPS (Network Policy Server / RADIUS)
    if (Get-WindowsFeature -Name NPAS -ErrorAction SilentlyContinue | Where-Object { $_.Installed }) {
        $detectedRoles += "NPS"
    }

    return $detectedRoles
}

# =============================================================================
# Start
# =============================================================================
Clear-Host
Write-Banner "Windows Server 2025 - Security Monitoring Deployment"

# Auto-detect roles if not specified
if (-not $ServerRoles) {
    Write-Log "Автоматичне визначення ролей сервера..." -Level Info
    $ServerRoles = Get-InstalledServerRoles
    if ($ServerRoles.Count -eq 0) {
        Write-Log "Ролі не знайдено (standalone server)" -Level Warning
    } else {
        Write-Log "Знайдено ролі: $($ServerRoles -join ', ')" -Level Success
    }
}

Write-Host "Конфігурація:" -ForegroundColor Yellow
Write-Host "  Сервер: $env:COMPUTERNAME"
Write-Host "  Loki URL: $LokiUrl"
Write-Host "  FleetDM: $(if($FleetUrl){'Enabled'}else{'Disabled'})"
Write-Host "  Sysmon: $(if($SkipSysmon){'Skip'}else{'Install'})"
Write-Host "  Hardening: $(if($SkipHardening){'Skip'}else{'Apply'})"
Write-Host "  Ролі: $(if($ServerRoles.Count -gt 0){$ServerRoles -join ', '}else{'None'})"
Write-Host ""

$confirm = Read-Host "Продовжити? (y/n)"
if ($confirm -ne 'y') {
    Write-Log "Скасовано користувачем" -Level Warning
    exit 0
}

$startTime = Get-Date
$totalSteps = 8 + $ServerRoles.Count
$currentStep = 0

# =============================================================================
# Step 1: Audit Policy
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Audit Policy Configuration"

try {
    & "$CommonDir\01-Set-AuditPolicy.ps1"
    Write-Log "Audit Policy налаштовано" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 2: PowerShell Logging
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: PowerShell Logging"

try {
    & "$CommonDir\02-Enable-PowerShellLogging.ps1"
    Write-Log "PowerShell Logging включено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 3: Sysmon
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Sysmon Installation"

if ($SkipSysmon) {
    Write-Log "Sysmon пропущено (-SkipSysmon)" -Level Warning
} else {
    try {
        & "$CommonDir\03-Install-Sysmon.ps1"
        Write-Log "Sysmon встановлено" -Level Success
    } catch {
        Write-Log "Помилка: $_" -Level Error
    }
}

# =============================================================================
# Step 4: Promtail
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Promtail Installation"

try {
    $promtailConfig = Join-Path $ScriptDir "promtail-server.yml"
    if (Test-Path $promtailConfig) {
        & "$CommonDir\04-Install-Promtail.ps1" -LokiUrl $LokiUrl -ConfigPath $promtailConfig
    } else {
        & "$CommonDir\04-Install-Promtail.ps1" -LokiUrl $LokiUrl
    }
    Write-Log "Promtail встановлено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 5: Windows Exporter
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Windows Exporter Installation"

try {
    & "$CommonDir\05-Install-WindowsExporter.ps1"
    Write-Log "Windows Exporter встановлено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 6: Server Hardening
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Server Hardening"

if ($SkipHardening) {
    Write-Log "Hardening пропущено (-SkipHardening)" -Level Warning
} else {
    try {
        $hardenScript = Join-Path $ScriptDir "01-Harden-Server.ps1"
        if (Test-Path $hardenScript) {
            & $hardenScript
            Write-Log "Server Hardening застосовано" -Level Success
        } else {
            Write-Log "Скрипт hardening не знайдено" -Level Warning
        }
    } catch {
        Write-Log "Помилка: $_" -Level Error
    }
}

# =============================================================================
# Step 7: Role-specific Logging
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Role-Specific Logging Configuration"

foreach ($role in $ServerRoles) {
    Write-Log "Налаштування логування для: $role" -Level Info

    switch ($role) {
        "ADDS" {
            try {
                $addsScript = Join-Path $ScriptDir "02-Configure-ADDSAudit.ps1"
                if (Test-Path $addsScript) {
                    & $addsScript
                    Write-Log "ADDS аудит налаштовано" -Level Success
                }
            } catch {
                Write-Log "Помилка ADDS: $_" -Level Error
            }
        }
        "DHCP" {
            try {
                $dhcpScript = Join-Path $ScriptDir "03-Configure-DHCPLogging.ps1"
                if (Test-Path $dhcpScript) {
                    & $dhcpScript
                    Write-Log "DHCP логування налаштовано" -Level Success
                }
            } catch {
                Write-Log "Помилка DHCP: $_" -Level Error
            }
        }
        "DNS" {
            try {
                $dnsScript = Join-Path $ScriptDir "04-Configure-DNSLogging.ps1"
                if (Test-Path $dnsScript) {
                    & $dnsScript
                    Write-Log "DNS логування налаштовано" -Level Success
                }
            } catch {
                Write-Log "Помилка DNS: $_" -Level Error
            }
        }
        "FileServer" {
            try {
                $fsScript = Join-Path $ScriptDir "05-Configure-FileServerAudit.ps1"
                if (Test-Path $fsScript) {
                    & $fsScript
                    Write-Log "File Server аудит налаштовано" -Level Success
                }
            } catch {
                Write-Log "Помилка FileServer: $_" -Level Error
            }
        }
        "NPS" {
            try {
                $npsScript = Join-Path $ScriptDir "06-Configure-NPSLogging.ps1"
                if (Test-Path $npsScript) {
                    & $npsScript
                    Write-Log "NPS логування налаштовано" -Level Success
                }
            } catch {
                Write-Log "Помилка NPS: $_" -Level Error
            }
        }
    }
}

# =============================================================================
# Step 8: Osquery (optional)
# =============================================================================
$currentStep++
Write-Banner "Step $currentStep/$totalSteps: Osquery Agent (Optional)"

if ($SkipOsquery -or -not $FleetUrl) {
    Write-Log "Osquery пропущено" -Level Warning
} else {
    if (-not $FleetEnrollSecret) {
        Write-Log "FleetEnrollSecret не вказано, osquery не встановлено" -Level Warning
    } else {
        try {
            & "$CommonDir\06-Install-OsqueryAgent.ps1" -FleetUrl $FleetUrl -EnrollSecret $FleetEnrollSecret
            Write-Log "Osquery встановлено" -Level Success
        } catch {
            Write-Log "Помилка: $_" -Level Error
        }
    }
}

# =============================================================================
# Summary
# =============================================================================
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  Deployment Completed!" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host ""
Write-Host "Тривалість: $($duration.Minutes) хв $($duration.Seconds) сек" -ForegroundColor Cyan
Write-Host ""
Write-Host "Встановлені компоненти:" -ForegroundColor Yellow

$services = @(
    @{Name = "Promtail"; Service = "Promtail"},
    @{Name = "Windows Exporter"; Service = "windows_exporter"},
    @{Name = "Sysmon"; Service = "Sysmon64"},
    @{Name = "Osquery"; Service = "osqueryd"}
)

foreach ($svc in $services) {
    $status = Get-Service -Name $svc.Service -ErrorAction SilentlyContinue
    if ($status) {
        $statusColor = if ($status.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "  $($svc.Name): " -NoNewline
        Write-Host $status.Status -ForegroundColor $statusColor
    }
}

Write-Host ""
Write-Host "Налаштовані ролі:" -ForegroundColor Yellow
foreach ($role in $ServerRoles) {
    Write-Host "  [+] $role"
}

Write-Host ""
Write-Host "Перевірка в Grafana:" -ForegroundColor Cyan
Write-Host "  1. Відкрийте http://<monitoring-server>:3000"
Write-Host "  2. Перейдіть в Explore → Loki"
Write-Host "  3. Запит: {host=`"$env:COMPUTERNAME`\", os_type=`"server`\"}"
Write-Host ""
