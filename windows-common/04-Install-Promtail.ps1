<#
.SYNOPSIS
    Встановлення Promtail як Windows Service.

.DESCRIPTION
    Завантажує та встановлює Promtail для відправки Windows Event Logs в Loki.
    Використовує NSSM для запуску як сервіс.

.PARAMETER LokiUrl
    URL сервера Loki (обов'язковий)

.PARAMETER ConfigPath
    Шлях до готової конфігурації Promtail (опціонально)

.PARAMETER PromtailVersion
    Версія Promtail для завантаження

.EXAMPLE
    .\04-Install-Promtail.ps1 -LokiUrl "http://10.0.1.2:3100"

.EXAMPLE
    .\04-Install-Promtail.ps1 -LokiUrl "http://10.0.1.2:3100" -ConfigPath ".\promtail.yml"

.NOTES
    Promtail надсилає логи до Loki для централізованого зберігання
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LokiUrl,

    [string]$ConfigPath,

    [string]$PromtailVersion = "2.9.3"
)

$ErrorActionPreference = "Stop"

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
Write-Host "  Promtail Installation for Windows" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\Program Files\Promtail"
$dataDir = "C:\ProgramData\Promtail"
$tempDir = "$env:TEMP\promtail_install"

# =============================================================================
# Перевірка існуючої установки
# =============================================================================
$existingService = Get-Service -Name "Promtail" -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Log "Promtail вже встановлено. Зупинка сервісу для оновлення..." -Level Warning
    Stop-Service -Name "Promtail" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# =============================================================================
# Створення директорій
# =============================================================================
Write-Log "Створення директорій..." -Level Info

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# =============================================================================
# Завантаження Promtail
# =============================================================================
Write-Log "Завантаження Promtail v$PromtailVersion..." -Level Info

$promtailUrl = "https://github.com/grafana/loki/releases/download/v$PromtailVersion/promtail-windows-amd64.exe.zip"
$promtailZip = "$tempDir\promtail.zip"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $promtailUrl -OutFile $promtailZip -UseBasicParsing
} catch {
    Write-Log "Помилка завантаження: $_" -Level Error
    exit 1
}

Expand-Archive -Path $promtailZip -DestinationPath $tempDir -Force
Copy-Item "$tempDir\promtail-windows-amd64.exe" -Destination "$installDir\promtail.exe" -Force

Write-Log "Promtail завантажено" -Level Success

# =============================================================================
# Завантаження NSSM
# =============================================================================
Write-Log "Завантаження NSSM..." -Level Info

$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmZip = "$tempDir\nssm.zip"

try {
    Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
    Expand-Archive -Path $nssmZip -DestinationPath $tempDir -Force
    Copy-Item "$tempDir\nssm-2.24\win64\nssm.exe" -Destination "$installDir\nssm.exe" -Force
} catch {
    Write-Log "Помилка завантаження NSSM: $_" -Level Error
    exit 1
}

Write-Log "NSSM завантажено" -Level Success

# =============================================================================
# Конфігурація Promtail
# =============================================================================
Write-Log "Створення конфігурації..." -Level Info

$hostname = $env:COMPUTERNAME

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    # Використання наданої конфігурації
    $configContent = Get-Content $ConfigPath -Raw
    $configContent = $configContent -replace '\$\{LOKI_URL\}', $LokiUrl
    $configContent = $configContent -replace '\$\{HOSTNAME\}', $hostname
    $configContent = $configContent -replace '\$\{COMPUTERNAME\}', $hostname
    $configContent | Out-File -FilePath "$installDir\config.yml" -Encoding UTF8
} else {
    # Генерація базової конфігурації
    $config = @"
# Promtail Configuration for Windows
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: C:\ProgramData\Promtail\positions.yaml

clients:
  - url: $LokiUrl/loki/api/v1/push
    batchwait: 1s
    batchsize: 1048576

scrape_configs:
  # Security Events - Authentication
  - job_name: windows_auth
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\auth-bookmark.xml
      eventlog_name: Security
      xpath_query: |
        Event[System[(
          EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or
          EventID=4648 or EventID=4672 or EventID=4776 or EventID=4740
        )]]
    labels:
      job: windows_auth
      host: $hostname
      category: authentication

  # Security Events - Account Management
  - job_name: windows_accounts
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\accounts-bookmark.xml
      eventlog_name: Security
      xpath_query: |
        Event[System[(
          EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or
          EventID=4725 or EventID=4726 or EventID=4727 or EventID=4728 or
          EventID=4729 or EventID=4730 or EventID=4731 or EventID=4732 or
          EventID=4733 or EventID=4734 or EventID=4735 or EventID=4738
        )]]
    labels:
      job: windows_accounts
      host: $hostname
      category: account_management

  # Security Events - Policy & Audit
  - job_name: windows_policy
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\policy-bookmark.xml
      eventlog_name: Security
      xpath_query: |
        Event[System[(
          EventID=1100 or EventID=1102 or EventID=4697 or EventID=4698 or
          EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702 or
          EventID=4719 or EventID=4688
        )]]
    labels:
      job: windows_policy
      host: $hostname
      category: policy_audit
      severity: high

  # System Events - Services
  - job_name: windows_system
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\system-bookmark.xml
      eventlog_name: System
      xpath_query: |
        Event[System[(
          EventID=7045 or EventID=7040 or EventID=7034 or EventID=7036
        )]]
    labels:
      job: windows_system
      host: $hostname
      category: services

  # PowerShell Events
  - job_name: windows_powershell
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\powershell-bookmark.xml
      eventlog_name: Microsoft-Windows-PowerShell/Operational
      xpath_query: |
        Event[System[(EventID=4103 or EventID=4104)]]
    labels:
      job: windows_powershell
      host: $hostname
      category: powershell
      severity: critical

  # Sysmon Events
  - job_name: windows_sysmon
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\sysmon-bookmark.xml
      eventlog_name: Microsoft-Windows-Sysmon/Operational
      xpath_query: |
        Event[System[(
          EventID=1 or EventID=3 or EventID=5 or EventID=7 or
          EventID=11 or EventID=12 or EventID=13 or EventID=22
        )]]
    labels:
      job: windows_sysmon
      host: $hostname
      category: sysmon
      severity: high

  # Windows Defender
  - job_name: windows_defender
    windows_events:
      use_incoming_timestamp: true
      bookmark_path: C:\ProgramData\Promtail\defender-bookmark.xml
      eventlog_name: Microsoft-Windows-Windows Defender/Operational
      xpath_query: |
        Event[System[(
          EventID=1006 or EventID=1007 or EventID=1116 or EventID=1117 or
          EventID=5001 or EventID=5007
        )]]
    labels:
      job: windows_defender
      host: $hostname
      category: antivirus
"@

    $config | Out-File -FilePath "$installDir\config.yml" -Encoding UTF8
}

Write-Log "Конфігурацію створено" -Level Success

# =============================================================================
# Встановлення сервісу
# =============================================================================
Write-Log "Встановлення Windows Service..." -Level Info

$nssmExe = "$installDir\nssm.exe"

# Видалення старого сервісу якщо є
& $nssmExe remove Promtail confirm 2>$null

# Встановлення нового сервісу
& $nssmExe install Promtail "$installDir\promtail.exe"
& $nssmExe set Promtail AppParameters "-config.file=`"$installDir\config.yml`""
& $nssmExe set Promtail AppDirectory $installDir
& $nssmExe set Promtail DisplayName "Promtail Log Collector"
& $nssmExe set Promtail Description "Collects Windows Event Logs and sends to Loki"
& $nssmExe set Promtail Start SERVICE_AUTO_START
& $nssmExe set Promtail AppStdout "$dataDir\promtail.log"
& $nssmExe set Promtail AppStderr "$dataDir\promtail-error.log"
& $nssmExe set Promtail AppRotateFiles 1
& $nssmExe set Promtail AppRotateBytes 10485760

# Запуск сервісу
Start-Service -Name "Promtail"

# =============================================================================
# Перевірка
# =============================================================================
Start-Sleep -Seconds 3

$service = Get-Service -Name "Promtail"

if ($service.Status -eq "Running") {
    Write-Log "Promtail сервіс запущено!" -Level Success
} else {
    Write-Log "Сервіс не запустився. Перевірте логи: $dataDir\promtail-error.log" -Level Error
    exit 1
}

# Очистка
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Promtail встановлено успішно!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Деталі:" -ForegroundColor Cyan
Write-Host "  Loki URL: $LokiUrl"
Write-Host "  Config: $installDir\config.yml"
Write-Host "  Logs: $dataDir\promtail.log"
Write-Host ""
Write-Host "Перевірка:" -ForegroundColor Cyan
Write-Host "  Get-Service Promtail"
Write-Host "  Invoke-WebRequest http://localhost:9080/ready"
Write-Host ""
