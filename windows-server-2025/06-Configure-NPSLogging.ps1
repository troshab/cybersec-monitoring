<#
.SYNOPSIS
    Налаштування логування Network Policy Server (RADIUS).

.DESCRIPTION
    Активує детальне логування NPS/RADIUS:
    - Accounting logging
    - Authentication logging
    - Event log налаштування
    - SQL logging (optional)

.EXAMPLE
    .\06-Configure-NPSLogging.ps1

.NOTES
    Запускати на NPS/RADIUS сервері
    Requires administrator rights
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$LogPath = "C:\Windows\System32\LogFiles\NPS",
    [switch]$EnableSqlLogging
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
Write-Host "  Network Policy Server (RADIUS) Logging Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Verification NPS сервісу
# =============================================================================
$npsService = Get-Service -Name IAS -ErrorAction SilentlyContinue
if (-not $npsService) {
    Write-Log "NPS сервіс (IAS) не знайдено" -Level Error
    Write-Log "Встановіть роль Network Policy and Access Services" -Level Info
    exit 1
}

Write-Log "NPS Server знайдено: $($npsService.Status)" -Level Success

# =============================================================================
# Creating directory for logs
# =============================================================================
Write-Log "Creating directory для NPS логів..." -Level Info

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    Write-Log "Створено: $LogPath" -Level Success
} else {
    Write-Log "Директорія існує: $LogPath" -Level Info
}

# =============================================================================
# Налаштування NPS Accounting
# =============================================================================
Write-Log "Налаштування NPS Accounting..." -Level Info

try {
    # Налаштування через netsh
    # Увімкнення логування в файл
    netsh nps set logging source=1 dest=file path="$LogPath" 2>$null

    # Accounting requests
    netsh nps set logging source=1 dest=file enable=yes 2>$null

    # Authentication requests
    netsh nps set logging source=2 dest=file enable=yes 2>$null

    # Periodic status
    netsh nps set logging source=4 dest=file enable=yes 2>$null

    Write-Log "NPS Accounting налаштовано" -Level Success

} catch {
    Write-Log "Помилка налаштування через netsh: $_" -Level Warning
}

# =============================================================================
# Налаштування через реєстр
# =============================================================================
Write-Log "Налаштування NPS через реєстр..." -Level Info

$npsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\IAS\Parameters"

try {
    # Accounting logging
    Set-ItemProperty -Path $npsRegPath -Name "Accounting" -Value 1 -Type DWord -Force

    # Authentication logging
    Set-ItemProperty -Path $npsRegPath -Name "Authentication" -Value 1 -Type DWord -Force

    # Log path
    Set-ItemProperty -Path $npsRegPath -Name "LogFileDir" -Value $LogPath -Type String -Force

    Write-Log "Реєстр NPS налаштовано" -Level Success
} catch {
    Write-Log "Помилка налаштування реєстру: $_" -Level Warning
}

# =============================================================================
# NPS Event Log
# =============================================================================
Write-Log "Налаштування NPS Event Log..." -Level Info

try {
    # Microsoft-Windows-Security-Auditing for NPS
    # Це частина Security Log

    # NPS-specific event log
    wevtutil sl "Microsoft-Windows-NetworkPolicy/Operational" /e:true /ms:134217728  # 128 MB

    Write-Log "NPS Event Log: 128 MB" -Level Success
} catch {
    Write-Log "NPS Event Log не знайдено" -Level Warning
}

# =============================================================================
# Audit Policy для NPS
# =============================================================================
Write-Log "Налаштування Audit Policy для NPS..." -Level Info

$npsAuditPolicies = @(
    @{SubCategory = "Network Policy Server"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Other Logon/Logoff Events"; Success = "enable"; Failure = "enable"}
)

foreach ($policy in $npsAuditPolicies) {
    $result = auditpol /set /subcategory:"$($policy.SubCategory)" /success:$($policy.Success) /failure:$($policy.Failure) 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Налаштовано: $($policy.SubCategory)" -Level Success
    }
}

# =============================================================================
# Налаштування формату логів
# =============================================================================
Write-Log "Налаштування формату NPS логів..." -Level Info

# IAS формат логів (DTS compliant)
$iasRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\IAS\Parameters\LogFile"

if (-not (Test-Path $iasRegPath)) {
    New-Item -Path $iasRegPath -Force | Out-Null
}

# Налаштування формату
Set-ItemProperty -Path $iasRegPath -Name "LogFormat" -Value 1 -Type DWord -Force  # IAS format
Set-ItemProperty -Path $iasRegPath -Name "LogPeriod" -Value 1 -Type DWord -Force  # Daily
Set-ItemProperty -Path $iasRegPath -Name "LogDelete" -Value 0 -Type DWord -Force  # Don't auto-delete

Write-Log "Формат логів: IAS (щоденні файли)" -Level Success

# =============================================================================
# SQL Logging (optional)
# =============================================================================
if ($EnableSqlLogging) {
    Write-Log "SQL Logging потребує додаткової конфігурації" -Level Warning
    Write-Log "Використовуйте NPS MMC для налаштування SQL connection" -Level Info
}

# =============================================================================
# Restart NPS
# =============================================================================
Write-Log "Restart NPS сервісу..." -Level Info

try {
    Restart-Service -Name IAS -Force
    Start-Sleep -Seconds 5

    $npsService = Get-Service -Name IAS
    if ($npsService.Status -eq "Running") {
        Write-Log "NPS сервіс перезапущено" -Level Success
    } else {
        Write-Log "NPS сервіс не запустився" -Level Error
    }
} catch {
    Write-Log "Помилка перезапуску: $_" -Level Error
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  NPS Logging Configuration Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Налаштування:" -ForegroundColor Cyan
Write-Host "  Log Directory: $LogPath"
Write-Host "  Format: IAS (Daily files)"
Write-Host "  Accounting: Enabled"
Write-Host "  Authentication: Enabled"
Write-Host ""
Write-Host "Важливі NPS Event IDs:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Authentication Events (Security Log):" -ForegroundColor Cyan
Write-Host "  6272 - NPS granted access"
Write-Host "  6273 - NPS denied access"
Write-Host "  6274 - NPS discarded request"
Write-Host "  6275 - NPS discarded accounting request"
Write-Host "  6276 - NPS quarantined user"
Write-Host "  6277 - NPS granted access (probation)"
Write-Host "  6278 - NPS granted full access"
Write-Host "  6279 - NPS locked user account"
Write-Host "  6280 - NPS unlocked user account"
Write-Host ""
Write-Host "RADIUS Accounting Events:" -ForegroundColor Cyan
Write-Host "  6281 - NPS accounting started"
Write-Host "  6282 - NPS accounting stopped"
Write-Host ""
Write-Host "NPS Log File Format (IAS):" -ForegroundColor Yellow
Write-Host "  Файли: IN<yymmdd>.log"
Write-Host "  Поля: ComputerName,ServiceName,Record-Date,Record-Time,"
Write-Host "        Packet-Type,User-Name,Fully-Qualified-User-Name,"
Write-Host "        Called-Station-ID,Calling-Station-ID,..."
Write-Host ""
Write-Host "Loki запити для NPS:" -ForegroundColor Yellow
Write-Host '  # Успішна автентифікація RADIUS'
Write-Host '  {job="windows_security"} |= "6272"'
Write-Host ""
Write-Host '  # Невдала автентифікація RADIUS'
Write-Host '  {job="windows_security"} |= "6273"'
Write-Host ""
Write-Host '  # VPN/Wi-Fi автентифікація'
Write-Host '  {job="windows_nps"} |~ "Access-Accept|Access-Reject"'
Write-Host ""
Write-Host "Типові use cases:" -ForegroundColor Cyan
Write-Host "  - Wi-Fi автентифікація (802.1X)"
Write-Host "  - VPN автентифікація"
Write-Host "  - Network Access Control (NAC)"
Write-Host "  - Switch/Router RADIUS"
Write-Host ""
