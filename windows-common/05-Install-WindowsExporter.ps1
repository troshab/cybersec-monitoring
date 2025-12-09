<#
.SYNOPSIS
    Встановлення Windows Exporter для Prometheus.

.DESCRIPTION
    Встановлює Windows Exporter для збору метрик системи (CPU, RAM, Disk, Network).
    Prometheus збирає ці метрики для моніторингу стану системи.

.PARAMETER ExporterVersion
    Версія Windows Exporter

.PARAMETER ListenPort
    Порт для експорту метрик (за замовчуванням 9182)

.PARAMETER Collectors
    Список collectors для включення

.EXAMPLE
    .\05-Install-WindowsExporter.ps1

.EXAMPLE
    .\05-Install-WindowsExporter.ps1 -ListenPort 9182 -Collectors "cpu,memory,logical_disk,net,service"

.NOTES
    Порт 9182 повинен бути відкритий в firewall для Prometheus
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ExporterVersion = "0.25.1",
    [int]$ListenPort = 9182,
    [string]$Collectors = "cpu,cs,logical_disk,memory,net,os,process,service,system,tcp"
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
Write-Host "  Windows Exporter Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\Program Files\windows_exporter"
$tempDir = "$env:TEMP\winexporter_install"

# =============================================================================
# Verification існуючої установки
# =============================================================================
$existingService = Get-Service -Name "windows_exporter" -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Log "Windows Exporter вже встановлено" -Level Warning
    $response = Read-Host "Перевстановити? (y/n)"
    if ($response -ne 'y') {
        exit 0
    }
    Write-Log "Зупинка сервісу..." -Level Info
    Stop-Service -Name "windows_exporter" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# =============================================================================
# Створення директорій
# =============================================================================
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# =============================================================================
# Завантаження
# =============================================================================
Write-Log "Завантаження Windows Exporter v$ExporterVersion..." -Level Info

$downloadUrl = "https://github.com/prometheus-community/windows_exporter/releases/download/v$ExporterVersion/windows_exporter-$ExporterVersion-amd64.msi"
$msiFile = "$tempDir\windows_exporter.msi"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiFile -UseBasicParsing
} catch {
    Write-Log "Download error: $_" -Level Error
    exit 1
}

Write-Log "Завантажено успішно" -Level Success

# =============================================================================
# Встановлення
# =============================================================================
Write-Log "Встановлення Windows Exporter..." -Level Info

$msiArgs = @(
    "/i", $msiFile,
    "/qn",
    "LISTEN_PORT=$ListenPort",
    "ENABLED_COLLECTORS=$Collectors"
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Log "Installation error MSI (code: $($process.ExitCode))" -Level Error
    exit 1
}

Write-Log "MSI встановлено" -Level Success

# =============================================================================
# Налаштування Firewall
# =============================================================================
Write-Log "Configuring Windows Firewall..." -Level Info

$ruleName = "Windows Exporter"

# Видалення старого правила
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# Створення нового правила
New-NetFirewallRule -DisplayName $ruleName `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $ListenPort `
    -Action Allow `
    -Profile Domain,Private `
    -Description "Allow Prometheus to scrape Windows Exporter metrics" | Out-Null

Write-Log "Firewall правило створено (порт $ListenPort)" -Level Success

# =============================================================================
# Запуск сервісу
# =============================================================================
Write-Log "Запуск сервісу..." -Level Info

Start-Service -Name "windows_exporter"

Start-Sleep -Seconds 3

$service = Get-Service -Name "windows_exporter"

if ($service.Status -eq "Running") {
    Write-Log "Windows Exporter запущено!" -Level Success
} else {
    Write-Log "Сервіс не запустився" -Level Error
    exit 1
}

# =============================================================================
# Verification метрик
# =============================================================================
Write-Log "Verification метрик..." -Level Info

try {
    $response = Invoke-WebRequest -Uri "http://localhost:$ListenPort/metrics" -UseBasicParsing -TimeoutSec 5
    $metricsCount = ($response.Content -split "`n" | Where-Object { $_ -match "^windows_" }).Count

    Write-Log "Received $metricsCount метрик" -Level Success
} catch {
    Write-Log "Не вдалося отримати метрики: $_" -Level Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows Exporter встановлено успішно!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Деталі:" -ForegroundColor Cyan
Write-Host "  Порт: $ListenPort"
Write-Host "  Collectors: $Collectors"
Write-Host "  Metrics URL: http://localhost:$ListenPort/metrics"
Write-Host ""
Write-Host "Prometheus scrape config:" -ForegroundColor Yellow
Write-Host "  - job_name: 'windows'"
Write-Host "    static_configs:"
Write-Host "      - targets: ['$($env:COMPUTERNAME):$ListenPort']"
Write-Host ""
