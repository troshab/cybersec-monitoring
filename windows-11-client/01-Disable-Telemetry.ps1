<#
.SYNOPSIS
    Disable unnecessary Windows 11 telemetry.

.DESCRIPTION
    Disables Windows 11 telemetry and diagnostic services,
    that may interfere with security monitoring or send
    data outside.

    Does NOT affect:
    - Windows Update
    - Windows Defender
    - Event Logging

.EXAMPLE
    .\01-Disable-Telemetry.ps1

.NOTES
    Run as administrator
    Some changes require a reboot
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
Write-Log "Configuring telemetry services..." -Level Info

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
            Write-Log "Disabled: $($svc.DisplayName)" -Level Success
        }
    } catch {
        Write-Log "Failed to disable: $($svc.Name)" -Level Warning
    }
}

# =============================================================================
# Scheduled Tasks телеметрії
# =============================================================================
Write-Log "Disabling telemetry tasks..." -Level Info

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
        Write-Log "Disabled task: $(Split-Path $task -Leaf)" -Level Success
    } catch {
        # Task might not exist
    }
}

# =============================================================================
# Реєстр - Телеметрія
# =============================================================================
Write-Log "Configuring registry..." -Level Info

$registrySettings = @(
    # Disabling telemetry (minimum level)
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
    # Disabling Advertising ID
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        Name = "DisabledByGroupPolicy"
        Value = 1
        Type = "DWord"
    },
    # Disabling feedback notifications
    @{
        Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
        Name = "NumberOfSIUFInPeriod"
        Value = 0
        Type = "DWord"
    },
    # Disabling Wi-Fi Sense
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        Name = "AutoConnectAllowedOEM"
        Value = 0
        Type = "DWord"
    },
    # Disabling Application Telemetry
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name = "AITEnable"
        Value = 0
        Type = "DWord"
    },
    # Disabling Inventory Collector
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name = "DisableInventory"
        Value = 1
        Type = "DWord"
    },
    # Disabling Steps Recorder
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
        Write-Log "Set: $($setting.Path)\$($setting.Name)" -Level Success
    } catch {
        Write-Log "Error: $($setting.Path)\$($setting.Name)" -Level Warning
    }
}

# =============================================================================
# Hosts file - блокування телеметричних доменів (optional)
# =============================================================================
Write-Log "Blocking telemetry domains..." -Level Info

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
        Write-Log "Telemetry domains blocked in hosts" -Level Success
    } else {
        Write-Log "Hosts already contains telemetry blocking" -Level Warning
    }
} catch {
    Write-Log "Failed to modify hosts: $_" -Level Warning
}

# =============================================================================
# Вимкнення Cortana
# =============================================================================
Write-Log "Configuring Cortana..." -Level Info

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
        Write-Log "Cortana configuration error" -Level Warning
    }
}

Write-Log "Cortana disabled" -Level Success

# =============================================================================
# Вимкнення OneDrive автозапуску
# =============================================================================
Write-Log "Configuring OneDrive..." -Level Info

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "OneDrive autostart disabled" -Level Success
} catch {
    Write-Log "OneDrive settings not applied" -Level Warning
}

# =============================================================================
# Privacy налаштування
# =============================================================================
Write-Log "Configuring Privacy..." -Level Info

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

Write-Log "Privacy settings applied" -Level Success

# =============================================================================
# Flush DNS cache
# =============================================================================
Write-Log "Cleanup DNS кешу..." -Level Info
Clear-DnsClientCache
Write-Log "DNS cache cleared" -Level Success

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Telemetry configured!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied:" -ForegroundColor Cyan
Write-Host "  - Disabled telemetry services"
Write-Host "  - Disabled data collection tasks"
Write-Host "  - Configured registry"
Write-Host "  - Blocked telemetry domains"
Write-Host "  - Disabled Cortana/OneDrive"
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - Reboot recommended"
Write-Host "  - Windows Update works normally"
Write-Host "  - Windows Defender works normally"
Write-Host ""
