<#
.SYNOPSIS
    Встановлення Grafana Alloy для збору логів Windows.

.DESCRIPTION
    Завантажує та встановлює Grafana Alloy (замінює deprecated Promtail).
    Alloy збирає Windows Event Logs та відправляє до Loki.

.PARAMETER LokiUrl
    URL Loki сервера (наприклад, http://10.0.1.2:3100)

.PARAMETER ConfigPath
    Шлях до локального конфіг файлу config.alloy

.EXAMPLE
    .\04-Install-Alloy.ps1 -LokiUrl "http://10.0.1.2:3100"

.EXAMPLE
    .\04-Install-Alloy.ps1 -ConfigPath "C:\temp\config.alloy"

.NOTES
    Потребує прав адміністратора
    Alloy 1.x (replaces deprecated Promtail)
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$LokiUrl = "http://10.0.1.2:3100",
    [string]$ConfigPath
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
Write-Host "  Grafana Alloy Installation" -ForegroundColor Cyan
Write-Host "  (Replaces deprecated Promtail)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\Program Files\GrafanaLabs\Alloy"
$dataDir = "C:\ProgramData\GrafanaLabs\Alloy"
$tempDir = "$env:TEMP\alloy_install"

# =============================================================================
# Перевірка чи вже встановлено
# =============================================================================
$existingService = Get-Service -Name "Alloy" -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Log "Alloy вже встановлено" -Level Warning
    Write-Log "Оновлення конфігурації..." -Level Info

    # Stop service for config update
    Stop-Service -Name "Alloy" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        Copy-Item $ConfigPath -Destination "$dataDir\config.alloy" -Force
        Write-Log "Конфігурацію оновлено з $ConfigPath" -Level Success
    }

    Start-Service -Name "Alloy"
    Write-Log "Alloy перезапущено" -Level Success
    exit 0
}

# =============================================================================
# Завантаження Alloy
# =============================================================================
Write-Log "Завантаження Grafana Alloy..." -Level Info

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Latest stable version
$alloyVersion = "1.5.1"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$downloadUrl = "https://github.com/grafana/alloy/releases/download/v${alloyVersion}/alloy-installer-windows-${arch}.exe.zip"
$zipPath = "$tempDir\alloy-installer.zip"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Write-Log "Завантажено Alloy v$alloyVersion" -Level Success
} catch {
    Write-Log "Помилка завантаження: $_" -Level Error
    exit 1
}

# =============================================================================
# Розпакування та встановлення
# =============================================================================
Write-Log "Встановлення Alloy..." -Level Info

Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

$installerPath = Get-ChildItem -Path $tempDir -Filter "alloy-installer-windows-*.exe" | Select-Object -First 1

if (-not $installerPath) {
    Write-Log "Installer не знайдено" -Level Error
    exit 1
}

# Run silent install
$installArgs = "/S"
$process = Start-Process -FilePath $installerPath.FullName -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Log "Помилка встановлення (код: $($process.ExitCode))" -Level Error
    exit 1
}

Write-Log "Alloy встановлено" -Level Success

# =============================================================================
# Конфігурація
# =============================================================================
Write-Log "Налаштування конфігурації..." -Level Info

# Create data directory
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# Determine config source
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    # Use provided config
    Copy-Item $ConfigPath -Destination "$dataDir\config.alloy" -Force
    Write-Log "Використовується конфігурація: $ConfigPath" -Level Info
} else {
    # Find config in script directory
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $parentDir = Split-Path -Parent $scriptDir

    # Try windows-11-client or windows-server-2025 directory
    $possibleConfigs = @(
        "$parentDir\windows-11-client\config.alloy",
        "$parentDir\windows-server-2025\config.alloy",
        "$scriptDir\..\windows-11-client\config.alloy",
        "$scriptDir\..\windows-server-2025\config.alloy"
    )

    $foundConfig = $null
    foreach ($cfg in $possibleConfigs) {
        if (Test-Path $cfg) {
            $foundConfig = $cfg
            break
        }
    }

    if ($foundConfig) {
        Copy-Item $foundConfig -Destination "$dataDir\config.alloy" -Force
        Write-Log "Використовується конфігурація: $foundConfig" -Level Info
    } else {
        Write-Log "Конфігурацію не знайдено! Створюю базову..." -Level Warning

        # Create minimal config
        $minimalConfig = @"
// Minimal Alloy configuration
loki.write "default" {
  endpoint {
    url = "$LokiUrl/loki/api/v1/push"
  }
}

loki.source.windowsevent "security" {
  eventlog_name = "Security"
  xpath_query   = "*"
  labels = {
    job  = "windows_security",
    host = env("COMPUTERNAME"),
  }
  forward_to = [loki.write.default.receiver]
}
"@
        $minimalConfig | Out-File -FilePath "$dataDir\config.alloy" -Encoding UTF8
    }
}

# Update Loki URL in config if needed
if ($LokiUrl) {
    $configContent = Get-Content "$dataDir\config.alloy" -Raw
    $configContent = $configContent -replace 'url\s*=\s*"http://[^"]+/loki/api/v1/push"', "url = `"$LokiUrl/loki/api/v1/push`""
    $configContent | Out-File -FilePath "$dataDir\config.alloy" -Encoding UTF8 -NoNewline
}

# =============================================================================
# Налаштування служби
# =============================================================================
Write-Log "Налаштування служби Windows..." -Level Info

# Configure service to use our config
$serviceName = "Alloy"

# Stop service if running
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Update service configuration via registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Alloy"
if (Test-Path $regPath) {
    $imagePath = "`"$installDir\alloy-windows-amd64.exe`" run `"$dataDir\config.alloy`" --storage.path=`"$dataDir\data`""
    Set-ItemProperty -Path $regPath -Name "ImagePath" -Value $imagePath
}

# =============================================================================
# Запуск служби
# =============================================================================
Write-Log "Запуск служби Alloy..." -Level Info

Start-Service -Name $serviceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq "Running") {
    Write-Log "Alloy запущено успішно!" -Level Success
} else {
    Write-Log "Служба Alloy не запустилась. Перевірте логи." -Level Warning
    Write-Log "Event Viewer -> Application and Services Logs -> Alloy" -Level Info
}

# =============================================================================
# Очистка
# =============================================================================
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# =============================================================================
# Результат
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Grafana Alloy встановлено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Директорія: $installDir" -ForegroundColor Cyan
Write-Host "Конфігурація: $dataDir\config.alloy" -ForegroundColor Cyan
Write-Host "Loki URL: $LokiUrl" -ForegroundColor Cyan
Write-Host ""
Write-Host "Команди:" -ForegroundColor Yellow
Write-Host "  Get-Service Alloy                    # Статус"
Write-Host "  Restart-Service Alloy                # Перезапуск"
Write-Host "  Get-Content '$dataDir\config.alloy'  # Конфігурація"
Write-Host ""
Write-Host "Логи: Event Viewer -> Application -> Alloy" -ForegroundColor Yellow
Write-Host ""
