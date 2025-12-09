<#
.SYNOPSIS
    Встановлення osquery агента для FleetDM.

.DESCRIPTION
    Встановлює osquery та налаштовує підключення до FleetDM сервера
    для централізованої інвентаризації endpoints.

.PARAMETER FleetUrl
    URL FleetDM сервера (обов'язковий)

.PARAMETER EnrollSecret
    Секрет для реєстрації (отримати з FleetDM UI)

.PARAMETER CertPath
    Шлях до TLS сертифіката FleetDM

.PARAMETER OsqueryVersion
    Версія osquery для встановлення

.EXAMPLE
    .\06-Install-OsqueryAgent.ps1 -FleetUrl "https://fleet.company.ua:8080" -EnrollSecret "abc123..."

.NOTES
    Вимагає попередньо розгорнутий FleetDM сервер
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FleetUrl,

    [Parameter(Mandatory = $true)]
    [string]$EnrollSecret,

    [string]$CertPath,

    [string]$OsqueryVersion = "5.12.1",

    # Використовувати для self-signed сертифікатів (lab/training environment)
    [switch]$Insecure
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
Write-Host "  Osquery Agent Installation for FleetDM" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\Program Files\osquery"
$tempDir = "$env:TEMP\osquery_install"

# Parse Fleet URL
$fleetUri = [System.Uri]$FleetUrl
$fleetHostname = $fleetUri.Host
$fleetPort = if ($fleetUri.Port -gt 0) { $fleetUri.Port } else { 8080 }

# =============================================================================
# Перевірка існуючої установки
# =============================================================================
$existingService = Get-Service -Name "osqueryd" -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Log "Osquery вже встановлено" -Level Warning
    Write-Log "Зупинка сервісу для оновлення..." -Level Info
    Stop-Service -Name "osqueryd" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# =============================================================================
# Створення директорій
# =============================================================================
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# =============================================================================
# Завантаження osquery
# =============================================================================
Write-Log "Завантаження osquery v$OsqueryVersion..." -Level Info

$downloadUrl = "https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi"
$msiFile = "$tempDir\osquery.msi"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiFile -UseBasicParsing
} catch {
    Write-Log "Помилка завантаження: $_" -Level Error
    exit 1
}

Write-Log "Завантажено успішно" -Level Success

# =============================================================================
# Встановлення MSI
# =============================================================================
Write-Log "Встановлення osquery..." -Level Info

$msiArgs = @("/i", $msiFile, "/qn")
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Log "Помилка встановлення MSI (код: $($process.ExitCode))" -Level Error
    exit 1
}

Write-Log "Osquery встановлено" -Level Success

# =============================================================================
# Завантаження сертифіката FleetDM
# =============================================================================
Write-Log "Налаштування TLS..." -Level Info

$certFile = "$installDir\fleet.crt"

if ($CertPath -and (Test-Path $CertPath)) {
    Copy-Item $CertPath -Destination $certFile -Force
} else {
    # Спроба завантажити сертифікат з сервера
    Write-Log "Завантаження сертифіката з $fleetHostname`:$fleetPort..." -Level Info

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($fleetHostname, $fleetPort)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($fleetHostname)
        $cert = $sslStream.RemoteCertificate
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

        $certPem = "-----BEGIN CERTIFICATE-----`n"
        $certPem += [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $certPem += "`n-----END CERTIFICATE-----"

        $certPem | Out-File -FilePath $certFile -Encoding ASCII

        $sslStream.Close()
        $tcpClient.Close()

        Write-Log "Сертифікат збережено" -Level Success
    } catch {
        Write-Log "Не вдалося отримати сертифікат: $_" -Level Warning
        Write-Log "Вкажіть шлях до сертифіката через -CertPath" -Level Warning
        Write-Log "Або використайте -Insecure для self-signed сертифікатів" -Level Warning
    }
}

# =============================================================================
# Створення конфігурації
# =============================================================================
Write-Log "Створення конфігурації..." -Level Info

# Enroll secret
$EnrollSecret | Out-File -FilePath "$installDir\enroll_secret" -Encoding ASCII -NoNewline

# Flags file
$tlsCertsFlag = if ($Insecure) { "" } else { "--tls_server_certs=$certFile" }
$flagsContent = @"
--tls_hostname=$fleetHostname`:$fleetPort
$tlsCertsFlag
--enroll_secret_path=$installDir\enroll_secret
--host_identifier=hostname
--enroll_tls_endpoint=/api/osquery/enroll
--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_refresh=10
--disable_distributed=false
--distributed_plugin=tls
--distributed_interval=10
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
"@

$flagsContent | Out-File -FilePath "$installDir\osquery.flags" -Encoding ASCII

Write-Log "Конфігурацію створено" -Level Success

# =============================================================================
# Запуск сервісу
# =============================================================================
Write-Log "Запуск сервісу osqueryd..." -Level Info

# Зупинка якщо запущено
Stop-Service -Name "osqueryd" -Force -ErrorAction SilentlyContinue

# Видалення старого сервісу
& "$installDir\osqueryd.exe" --uninstall 2>$null

# Реєстрація сервісу
& "$installDir\osqueryd.exe" --install --flagfile="$installDir\osquery.flags"

Start-Sleep -Seconds 2

# Запуск
Start-Service -Name "osqueryd"

Start-Sleep -Seconds 3

$service = Get-Service -Name "osqueryd"

if ($service.Status -eq "Running") {
    Write-Log "Osquery сервіс запущено!" -Level Success
} else {
    Write-Log "Сервіс не запустився" -Level Error
    Write-Log "Перевірте логи: $installDir\osqueryd.results.log" -Level Info
}

# =============================================================================
# Тест osqueryi
# =============================================================================
Write-Log "Тест osquery..." -Level Info

try {
    $osqueryResult = & "$installDir\osqueryi.exe" --json "SELECT * FROM system_info" 2>$null | ConvertFrom-Json
    if ($osqueryResult) {
        Write-Log "Osquery працює: $($osqueryResult.hostname)" -Level Success
    }
} catch {
    Write-Log "Osqueryi не відповідає (це може бути нормально)" -Level Warning
}

# =============================================================================
# Очистка
# =============================================================================
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Osquery Agent встановлено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Деталі:" -ForegroundColor Cyan
Write-Host "  FleetDM: $FleetUrl"
Write-Host "  Install Dir: $installDir"
Write-Host ""
Write-Host "Перевірка:" -ForegroundColor Cyan
Write-Host "  1. Відкрийте FleetDM: $FleetUrl"
Write-Host "  2. Перейдіть в Hosts"
Write-Host "  3. Цей комп'ютер повинен з'явитись протягом хвилини"
Write-Host ""
