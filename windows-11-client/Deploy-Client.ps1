<#
.SYNOPSIS
    Головний скрипт розгортання моніторингу на Windows 11 клієнті.

.DESCRIPTION
    Автоматично виконує всі кроки налаштування:
    1. Audit Policy
    2. PowerShell Logging
    3. Sysmon
    4. Grafana Alloy (log collector)
    5. Windows Exporter
    6. Osquery (опціонально)

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

.EXAMPLE
    .\Deploy-Client.ps1 -LokiUrl "http://10.0.1.2:3100"

.EXAMPLE
    .\Deploy-Client.ps1 -LokiUrl "http://10.0.1.2:3100" -FleetUrl "https://10.0.1.2:8080" -FleetEnrollSecret "secret"

.NOTES
    Запускати від адміністратора
    Час виконання: ~5-10 хвилин
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LokiUrl,

    [string]$FleetUrl,

    [string]$FleetEnrollSecret,

    [switch]$SkipSysmon,

    [switch]$SkipOsquery
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
# Start
# =============================================================================
Clear-Host
Write-Banner "Windows 11 Client - Security Monitoring Deployment"

Write-Host "Конфігурація:" -ForegroundColor Yellow
Write-Host "  Комп'ютер: $env:COMPUTERNAME"
Write-Host "  Loki URL: $LokiUrl"
Write-Host "  FleetDM: $(if($FleetUrl){'Enabled'}else{'Disabled'})"
Write-Host "  Sysmon: $(if($SkipSysmon){'Skip'}else{'Install'})"
Write-Host ""

$confirm = Read-Host "Продовжити? (y/n)"
if ($confirm -ne 'y') {
    Write-Log "Скасовано користувачем" -Level Warning
    exit 0
}

$startTime = Get-Date

# =============================================================================
# Step 1: Audit Policy
# =============================================================================
Write-Banner "Step 1/6: Audit Policy Configuration"

try {
    & "$CommonDir\01-Set-AuditPolicy.ps1"
    Write-Log "Audit Policy налаштовано" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 2: PowerShell Logging
# =============================================================================
Write-Banner "Step 2/6: PowerShell Logging"

try {
    & "$CommonDir\02-Enable-PowerShellLogging.ps1"
    Write-Log "PowerShell Logging включено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 3: Sysmon
# =============================================================================
Write-Banner "Step 3/6: Sysmon Installation"

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
# Step 4: Grafana Alloy (replaces deprecated Promtail)
# =============================================================================
Write-Banner "Step 4/6: Grafana Alloy Installation"

try {
    $alloyConfig = Join-Path $ScriptDir "config.alloy"
    if (Test-Path $alloyConfig) {
        & "$CommonDir\04-Install-Alloy.ps1" -LokiUrl $LokiUrl -ConfigPath $alloyConfig
    } else {
        & "$CommonDir\04-Install-Alloy.ps1" -LokiUrl $LokiUrl
    }
    Write-Log "Grafana Alloy встановлено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 5: Windows Exporter
# =============================================================================
Write-Banner "Step 5/6: Windows Exporter Installation"

try {
    & "$CommonDir\05-Install-WindowsExporter.ps1"
    Write-Log "Windows Exporter встановлено" -Level Success
} catch {
    Write-Log "Помилка: $_" -Level Error
}

# =============================================================================
# Step 6: Osquery (optional)
# =============================================================================
Write-Banner "Step 6/6: Osquery Agent (Optional)"

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
    @{Name = "Grafana Alloy"; Service = "Alloy"},
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
Write-Host "Перевірка в Grafana:" -ForegroundColor Cyan
Write-Host "  1. Відкрийте http://<monitoring-server>:3000"
Write-Host "  2. Перейдіть в Explore → Loki"
Write-Host "  3. Запит: {host=`"$env:COMPUTERNAME`"}"
Write-Host ""
