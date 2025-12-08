<#
.SYNOPSIS
    Вимкнення зайвої телеметрії Windows 11.

.DESCRIPTION
    Вимикає телеметрію та діагностичні служби Windows 11,
    що можуть заважати безпековому моніторингу або надсилати
    дані назовні.

    НЕ впливає на:
    - Windows Update
    - Windows Defender
    - Event Logging

.EXAMPLE
    .\01-Disable-Telemetry.ps1

.NOTES
    Запускати від адміністратора
    Деякі зміни потребують перезавантаження
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

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
Write-Host "  Windows 11 Telemetry Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Служби телеметрії
# =============================================================================
Write-Log "Налаштування служб телеметрії..." -Level Info

$telemetryServices = @(
    @{Name = "DiagTrack"; DisplayName = "Connected User Experiences and Telemetry"},
    @{Name = "dmwappushservice"; DisplayName = "Device Management WAP Push"},
    @{Name = "diagnosticshub.standardcollector.service"; DisplayName = "Diagnostics Hub Standard Collector"}
)

foreach ($svc in $telemetryServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Вимкнено: $($svc.DisplayName)" -Level Success
        }
    } catch {
        Write-Log "Не вдалося вимкнути: $($svc.Name)" -Level Warning
    }
}

# =============================================================================
# Scheduled Tasks телеметрії
# =============================================================================
Write-Log "Вимкнення задач телеметрії..." -Level Info

$telemetryTasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
)

foreach ($task in $telemetryTasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Вимкнено задачу: $(Split-Path $task -Leaf)" -Level Success
    } catch {
        # Task might not exist
    }
}

# =============================================================================
# Реєстр - Телеметрія
# =============================================================================
Write-Log "Налаштування реєстру..." -Level Info

$registrySettings = @(
    # Вимкнення телеметрії (мінімальний рівень)
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Name = "AllowTelemetry"
        Value = 0
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        Name = "AllowTelemetry"
        Value = 0
        Type = "DWord"
    },
    # Вимкнення Advertising ID
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        Name = "DisabledByGroupPolicy"
        Value = 1
        Type = "DWord"
    },
    # Вимкнення feedback notifications
    @{
        Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
        Name = "NumberOfSIUFInPeriod"
        Value = 0
        Type = "DWord"
    },
    # Вимкнення Wi-Fi Sense
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        Name = "AutoConnectAllowedOEM"
        Value = 0
        Type = "DWord"
    },
    # Вимкнення Application Telemetry
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name = "AITEnable"
        Value = 0
        Type = "DWord"
    },
    # Вимкнення Inventory Collector
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name = "DisableInventory"
        Value = 1
        Type = "DWord"
    },
    # Вимкнення Steps Recorder
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name = "DisableUAR"
        Value = 1
        Type = "DWord"
    }
)

foreach ($setting in $registrySettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
        Write-Log "Встановлено: $($setting.Path)\$($setting.Name)" -Level Success
    } catch {
        Write-Log "Помилка: $($setting.Path)\$($setting.Name)" -Level Warning
    }
}

# =============================================================================
# Hosts file - блокування телеметричних доменів (опціонально)
# =============================================================================
Write-Log "Блокування телеметричних доменів..." -Level Info

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$telemetryDomains = @(
    "# Windows Telemetry Blocking (added by security script)",
    "0.0.0.0 vortex.data.microsoft.com",
    "0.0.0.0 vortex-win.data.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 oca.telemetry.microsoft.com",
    "0.0.0.0 oca.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 sqm.telemetry.microsoft.com",
    "0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 watson.telemetry.microsoft.com",
    "0.0.0.0 watson.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 redir.metaservices.microsoft.com",
    "0.0.0.0 choice.microsoft.com",
    "0.0.0.0 choice.microsoft.com.nsatc.net",
    "0.0.0.0 df.telemetry.microsoft.com",
    "0.0.0.0 reports.wes.df.telemetry.microsoft.com",
    "0.0.0.0 services.wes.df.telemetry.microsoft.com",
    "0.0.0.0 sqm.df.telemetry.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com",
    "0.0.0.0 watson.ppe.telemetry.microsoft.com",
    "0.0.0.0 telemetry.appex.bing.net",
    "0.0.0.0 telemetry.urs.microsoft.com",
    "0.0.0.0 settings-sandbox.data.microsoft.com",
    "# End Windows Telemetry Blocking"
)

try {
    $hostsContent = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue

    if ($hostsContent -notmatch "Windows Telemetry Blocking") {
        # Backup hosts file
        Copy-Item $hostsFile "$hostsFile.backup.$(Get-Date -Format 'yyyyMMdd')" -Force

        # Add telemetry blocks
        Add-Content -Path $hostsFile -Value "" -Force
        foreach ($domain in $telemetryDomains) {
            Add-Content -Path $hostsFile -Value $domain -Force
        }
        Write-Log "Телеметричні домени заблоковано в hosts" -Level Success
    } else {
        Write-Log "Hosts вже містить блокування телеметрії" -Level Warning
    }
} catch {
    Write-Log "Не вдалося модифікувати hosts: $_" -Level Warning
}

# =============================================================================
# Вимкнення Cortana
# =============================================================================
Write-Log "Налаштування Cortana..." -Level Info

$cortanaSettings = @(
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Name = "AllowCortana"
        Value = 0
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Name = "DisableWebSearch"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Name = "ConnectedSearchUseWeb"
        Value = 0
        Type = "DWord"
    }
)

foreach ($setting in $cortanaSettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
    } catch {
        Write-Log "Помилка Cortana налаштування" -Level Warning
    }
}

Write-Log "Cortana вимкнено" -Level Success

# =============================================================================
# Вимкнення OneDrive автозапуску
# =============================================================================
Write-Log "Налаштування OneDrive..." -Level Info

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "OneDrive автозапуск вимкнено" -Level Success
} catch {
    Write-Log "OneDrive налаштування не застосовано" -Level Warning
}

# =============================================================================
# Privacy налаштування
# =============================================================================
Write-Log "Налаштування Privacy..." -Level Info

$privacySettings = @(
    # Location
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; Value = 1},
    # Camera
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"; Name = "AllowCamera"; Value = 0},
    # Activity History
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0},
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0},
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0}
)

foreach ($setting in $privacySettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
    } catch {
        # Ignore errors for optional settings
    }
}

Write-Log "Privacy налаштування застосовано" -Level Success

# =============================================================================
# Flush DNS cache
# =============================================================================
Write-Log "Очистка DNS кешу..." -Level Info
Clear-DnsClientCache
Write-Log "DNS кеш очищено" -Level Success

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Телеметрія налаштована!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Застосовано:" -ForegroundColor Cyan
Write-Host "  - Вимкнено служби телеметрії"
Write-Host "  - Вимкнено задачі збору даних"
Write-Host "  - Налаштовано реєстр"
Write-Host "  - Заблоковано телеметричні домени"
Write-Host "  - Вимкнено Cortana/OneDrive"
Write-Host ""
Write-Host "ВАЖЛИВО:" -ForegroundColor Yellow
Write-Host "  - Рекомендується перезавантаження"
Write-Host "  - Windows Update працює нормально"
Write-Host "  - Windows Defender працює нормально"
Write-Host ""
