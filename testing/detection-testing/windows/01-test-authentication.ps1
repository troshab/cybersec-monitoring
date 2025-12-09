<#
.SYNOPSIS
    Тестування подій автентифікації (Event 4624, 4625, 4672, 4776).

.DESCRIPTION
    Генерує події автентифікації для тестування виявлення:
    - Успішні входи (4624)
    - Невдалі спроби входу (4625)
    - Призначення привілеїв (4672)
    - NTLM автентифікація (4776)

.EXAMPLE
    .\01-test-authentication.ps1

.NOTES
    Запускати від адміністратора
    Тільки для тестового середовища!
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]$FailedAttempts = 5,
    [string]$TestUser = "TestAuthUser"
)

$ErrorActionPreference = "Continue"

function Write-TestLog {
    param([string]$Message, [string]$Status = 'Info')
    $colors = @{ 'Info' = 'Cyan'; 'Success' = 'Green'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $prefix = @{ 'Info' = '[TEST]'; 'Success' = '[PASS]'; 'Warning' = '[WARN]'; 'Error' = '[FAIL]' }
    Write-Host "$($prefix[$Status]) $Message" -ForegroundColor $colors[$Status]
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  Authentication Events Test (4624, 4625, 4672, 4776)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# =============================================================================
# Test 1: Successful Logon (4624)
# =============================================================================
Write-TestLog "Test 1: Генерація успішного входу (Event 4624)..." -Status Info

# Поточний успішний вхід вже згенерував 4624
# Додатково запустимо процес від імені системи
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami" -WindowStyle Hidden -Wait
    Write-TestLog "Event 4624 має з'явитись в Security Log" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 2: Failed Logon (4625) - Brute Force Simulation
# =============================================================================
Write-TestLog "Test 2: Генерація невдалих входів (Event 4625)..." -Status Info
Write-TestLog "Симуляція $FailedAttempts невдалих спроб входу..." -Status Info

for ($i = 1; $i -le $FailedAttempts; $i++) {
    Write-TestLog "Спроба $i/$FailedAttempts..." -Status Info

    # Метод 1: net use з неправильним паролем
    $randomUser = "nonexistent_user_$i"
    $result = net use \\localhost\IPC$ /user:$randomUser "WrongPassword123!" 2>&1

    # Метод 2: runas з неправильними credentials (інтерактивно не працює)
    # Використаємо WMI для симуляції

    Start-Sleep -Milliseconds 500
}

Write-TestLog "$FailedAttempts подій 4625 мають з'явитись в Security Log" -Status Success

# =============================================================================
# Test 3: Account Lockout Attempt (4740)
# =============================================================================
Write-TestLog "Test 3: Спроба блокування акаунту (Event 4740)..." -Status Info

# Створення тестового користувача
try {
    $testPassword = ConvertTo-SecureString "TestP@ssw0rd123!" -AsPlainText -Force
    New-LocalUser -Name $TestUser -Password $testPassword -Description "Test Auth User" -ErrorAction SilentlyContinue

    # Багато невдалих спроб для тригеру lockout (якщо policy дозволяє)
    for ($i = 1; $i -le 10; $i++) {
        net use \\localhost\IPC$ /user:$TestUser "WrongPassword!" 2>&1 | Out-Null
    }

    Write-TestLog "Спроби блокування виконано (залежить від lockout policy)" -Status Success
} catch {
    Write-TestLog "Помилка створення тестового користувача: $_" -Status Warning
}

# =============================================================================
# Test 4: Special Privileges (4672)
# =============================================================================
Write-TestLog "Test 4: Призначення спеціальних привілеїв (Event 4672)..." -Status Info

# Запуск процесу з підвищеними правами генерує 4672
try {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-Command", "Get-Process | Out-Null" -Verb RunAs -WindowStyle Hidden -Wait -ErrorAction Stop
    Write-TestLog "Event 4672 має з'явитись при підвищенні прав" -Status Success
} catch {
    Write-TestLog "Не вдалось запустити процес (UAC?): $_" -Status Warning
}

# =============================================================================
# Test 5: NTLM Authentication (4776)
# =============================================================================
Write-TestLog "Test 5: NTLM автентифікація (Event 4776)..." -Status Info

# NTLM автентифікація через network logon
try {
    # Спроба підключення до localhost через SMB
    Get-ChildItem "\\$env:COMPUTERNAME\C$" -ErrorAction SilentlyContinue | Out-Null
    Write-TestLog "Event 4776 має з'явитись (NTLM auth)" -Status Success
} catch {
    Write-TestLog "NTLM тест потребує мережевого доступу" -Status Warning
}

# =============================================================================
# Test 6: Logon with Explicit Credentials (4648)
# =============================================================================
Write-TestLog "Test 6: Вхід з explicit credentials (Event 4648)..." -Status Info

try {
    # Створення credential object (не виконуємо реальний логін для безпеки)
    Write-TestLog "Event 4648 генерується при runas або network logon з credentials" -Status Info
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Write-TestLog "Очистка тестових даних..." -Status Info

try {
    # Видалення тестового користувача
    Remove-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
    Write-TestLog "Тестовий користувач $TestUser видалено" -Status Success
} catch {
    Write-TestLog "Користувач не існує або вже видалено" -Status Warning
}

# Очистка IPC$ підключень
net use * /delete /y 2>&1 | Out-Null

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

# Перевірка останніх подій
$events = @(
    @{Id = 4624; Name = "Successful Logon"},
    @{Id = 4625; Name = "Failed Logon"},
    @{Id = 4672; Name = "Special Privileges"},
    @{Id = 4776; Name = "NTLM Auth"}
)

foreach ($event in $events) {
    try {
        $count = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$event.Id; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
        Write-Host "  Event $($event.Id) ($($event.Name)): $count подій за останні 5 хв" -ForegroundColor $(if($count -gt 0){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  Event $($event.Id): не знайдено" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_auth"} |= "4625"'
Write-Host '  {job="windows_auth", host="'$env:COMPUTERNAME'"}'
Write-Host ""
