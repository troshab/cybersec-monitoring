<#
.SYNOPSIS
    Встановлення та налаштування Sysmon.

.DESCRIPTION
    Завантажує та встановлює Sysmon з конфігурацією SwiftOnSecurity
    для детального моніторингу процесів, мережевих з'єднань, файлів тощо.

    Sysmon Events:
    - Event 1: Process creation
    - Event 3: Network connection
    - Event 7: Image loaded
    - Event 11: File created
    - Event 12/13: Registry changes
    - Event 22: DNS query

.PARAMETER ConfigUrl
    URL до конфігураційного файлу (за замовчуванням SwiftOnSecurity)

.PARAMETER ConfigPath
    Локальний шлях до конфігурації (якщо вже є)

.EXAMPLE
    .\03-Install-Sysmon.ps1
    Встановлює Sysmon з конфігурацією SwiftOnSecurity

.EXAMPLE
    .\03-Install-Sysmon.ps1 -ConfigPath "C:\Config\sysmon.xml"
    Використовує власну конфігурацію

.NOTES
    Потребує прав адміністратора
    Sysmon працює як драйвер - потребує перезавантаження для деяких змін
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
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
Write-Host "  Sysmon Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$sysmonDir = "C:\Program Files\Sysmon"
$tempDir = "$env:TEMP\sysmon_install"

# =============================================================================
# Перевірка чи вже встановлено
# =============================================================================
$existingSysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

if ($existingSysmon) {
    Write-Log "Sysmon вже встановлено: $($existingSysmon.Name)" -Level Warning
    Write-Log "Оновлення конфігурації..." -Level Info

    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        & "$sysmonDir\Sysmon64.exe" -c $ConfigPath
    } else {
        # Завантаження нової конфігурації
        $tempConfig = "$tempDir\sysmonconfig.xml"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $tempConfig -UseBasicParsing
        & "$sysmonDir\Sysmon64.exe" -c $tempConfig
    }

    Write-Log "Конфігурацію оновлено" -Level Success
    exit 0
}

# =============================================================================
# Завантаження Sysmon
# =============================================================================
Write-Log "Завантаження Sysmon..." -Level Info

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$tempDir\Sysmon.zip"

try {
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
} catch {
    Write-Log "Помилка завантаження: $_" -Level Error
    exit 1
}

# Розпакування
Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force

# =============================================================================
# Завантаження конфігурації
# =============================================================================
Write-Log "Завантаження конфігурації..." -Level Info

$configFile = "$tempDir\sysmonconfig.xml"

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    Copy-Item $ConfigPath -Destination $configFile
    Write-Log "Використовується локальна конфігурація: $ConfigPath" -Level Info
} else {
    try {
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $configFile -UseBasicParsing
        Write-Log "Завантажено SwiftOnSecurity конфігурацію" -Level Success
    } catch {
        Write-Log "Помилка завантаження конфігурації: $_" -Level Error
        exit 1
    }
}

# =============================================================================
# Встановлення
# =============================================================================
Write-Log "Встановлення Sysmon..." -Level Info

# Створення директорії
New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null

# Копіювання файлів
Copy-Item "$tempDir\Sysmon64.exe" -Destination $sysmonDir
Copy-Item "$tempDir\Sysmon.exe" -Destination $sysmonDir
Copy-Item $configFile -Destination "$sysmonDir\sysmonconfig.xml"

# Встановлення з конфігурацією
$sysmonExe = "$sysmonDir\Sysmon64.exe"

$installArgs = @(
    "-accepteula",
    "-i",
    "$sysmonDir\sysmonconfig.xml"
)

$process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Log "Помилка встановлення (код: $($process.ExitCode))" -Level Error
    exit 1
}

# =============================================================================
# Перевірка
# =============================================================================
Start-Sleep -Seconds 3

$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Log "Sysmon встановлено та запущено!" -Level Success
} else {
    Write-Log "Sysmon встановлено, але сервіс не запущено" -Level Warning
    Start-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}

# Тест генерації подій
Write-Log "Перевірка генерації подій..." -Level Info

try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
    Write-Log "Отримано $($events.Count) подій Sysmon" -Level Success
} catch {
    Write-Log "Поки немає подій (це нормально для щойно встановленого Sysmon)" -Level Warning
}

# =============================================================================
# Очистка
# =============================================================================
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Sysmon встановлено успішно!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Sysmon Events:" -ForegroundColor Cyan
Write-Host "  Event 1  - Process creation (з командним рядком)"
Write-Host "  Event 3  - Network connection"
Write-Host "  Event 7  - Image loaded (DLL)"
Write-Host "  Event 11 - File created"
Write-Host "  Event 12 - Registry object created/deleted"
Write-Host "  Event 13 - Registry value set"
Write-Host "  Event 22 - DNS query"
Write-Host ""
Write-Host "Перевірка:" -ForegroundColor Cyan
Write-Host '  Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10'
Write-Host ""
