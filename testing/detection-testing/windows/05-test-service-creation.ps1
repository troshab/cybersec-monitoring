<#
.SYNOPSIS
    Тестування подій створення сервісів (Event 7045, 4697).

.DESCRIPTION
    Генерує події створення та зміни сервісів:
    - New Service Installation (7045)
    - Service Configuration Change (7040)
    - Scheduled Task Service (4697)

.EXAMPLE
    .\05-test-service-creation.ps1

.NOTES
    Запускати від адміністратора
    Сервіси автоматично видаляються після тесту
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

function Write-TestLog {
    param([string]$Message, [string]$Status = 'Info')
    $colors = @{ 'Info' = 'Cyan'; 'Success' = 'Green'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $prefix = @{ 'Info' = '[TEST]'; 'Success' = '[PASS]'; 'Warning' = '[WARN]'; 'Error' = '[FAIL]' }
    Write-Host "$($prefix[$Status]) $Message" -ForegroundColor $colors[$Status]
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  Service Creation Test (7045, 7040, 4697)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

$testServiceName = "TestSecurityService"
$testServiceName2 = "TestSecurityService2"

# =============================================================================
# Test 1: Create New Service (7045)
# =============================================================================
Write-TestLog "Test 1: Створення нового сервісу (Event 7045)..." -Status Info

try {
    # Видалення якщо існує
    sc.exe delete $testServiceName 2>&1 | Out-Null

    # Створення сервісу через sc.exe
    $result = sc.exe create $testServiceName binPath= "C:\Windows\System32\cmd.exe /c echo test" start= demand DisplayName= "Test Security Service" 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-TestLog "Сервіс $testServiceName створено (Event 7045)" -Status Success
    } else {
        Write-TestLog "Помилка створення: $result" -Status Warning
    }
} catch {
    Write-TestLog "Помилка: $_" -Status Error
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 2: Create Service with PowerShell (7045)
# =============================================================================
Write-TestLog "Test 2: Створення сервісу через PowerShell..." -Status Info

try {
    # Видалення якщо існує
    sc.exe delete $testServiceName2 2>&1 | Out-Null

    New-Service -Name $testServiceName2 `
        -BinaryPathName "C:\Windows\System32\cmd.exe" `
        -DisplayName "Test Security Service 2" `
        -Description "Test service for security monitoring" `
        -StartupType Manual `
        -ErrorAction Stop | Out-Null

    Write-TestLog "Сервіс $testServiceName2 створено через PowerShell" -Status Success
} catch {
    Write-TestLog "Помилка PowerShell: $_" -Status Warning
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 3: Change Service Configuration (7040)
# =============================================================================
Write-TestLog "Test 3: Зміна конфігурації сервісу (Event 7040)..." -Status Info

try {
    # Зміна типу запуску
    Set-Service -Name $testServiceName -StartupType Automatic -ErrorAction Stop
    Write-TestLog "Змінено StartupType на Automatic (Event 7040)" -Status Success
} catch {
    Write-TestLog "Помилка зміни: $_" -Status Warning
}

Start-Sleep -Seconds 1

try {
    # Зміна назад
    Set-Service -Name $testServiceName -StartupType Manual -ErrorAction Stop
    Write-TestLog "Змінено StartupType на Manual (Event 7040)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 4: Suspicious Service Paths
# =============================================================================
Write-TestLog "Test 4: Сервіс з підозрілим шляхом..." -Status Info

$suspiciousService = "TestSuspiciousService"
try {
    sc.exe delete $suspiciousService 2>&1 | Out-Null

    # Шлях з пробілом без лапок (класична вразливість)
    $result = sc.exe create $suspiciousService binPath= "C:\Program Files\Test Service\service.exe" start= demand 2>&1

    Write-TestLog "Створено сервіс з unquoted path (вразливість!)" -Status Warning
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 5: Service with PowerShell in path
# =============================================================================
Write-TestLog "Test 5: Сервіс з PowerShell у шляху..." -Status Info

$psService = "TestPSService"
try {
    sc.exe delete $psService 2>&1 | Out-Null

    $result = sc.exe create $psService binPath= "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command Get-Date" start= demand 2>&1

    Write-TestLog "Створено сервіс з PowerShell (SUSPICIOUS!)" -Status Warning
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Write-TestLog "Очистка тестових сервісів..." -Status Info

$servicesToRemove = @($testServiceName, $testServiceName2, $suspiciousService, $psService)

foreach ($svc in $servicesToRemove) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc 2>&1 | Out-Null
        Write-TestLog "Видалено: $svc" -Status Success
    } catch {
        Write-TestLog "Сервіс $svc не існує або помилка" -Status Warning
    }
}

# =============================================================================
# Verification
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Тест завершено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Перевірка подій:" -ForegroundColor Cyan
Write-Host ""

# System Log - Event 7045 (Service Installed)
try {
    $count7045 = (Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 7045 (Service Installed): $count7045 подій" -ForegroundColor $(if($count7045 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 7045: не знайдено" -ForegroundColor Yellow
}

# System Log - Event 7040 (Service Config Changed)
try {
    $count7040 = (Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 7040 (Service Changed): $count7040 подій" -ForegroundColor $(if($count7040 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 7040: не знайдено" -ForegroundColor Yellow
}

# Security Log - Event 4697 (Service Installed via Security)
try {
    $count4697 = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 4697 (Security Service Install): $count4697 подій" -ForegroundColor $(if($count4697 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 4697: не знайдено (потребує аудиту)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_services"} |= "7045"'
Write-Host '  {job="windows_services"} |~ "TestSecurityService"'
Write-Host '  {job="windows_persistence"} |= "4697"'
Write-Host ""
