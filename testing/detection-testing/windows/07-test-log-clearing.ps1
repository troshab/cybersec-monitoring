<#
.SYNOPSIS
    Тестування подій очищення журналів (Event 1102, 1100).

.DESCRIPTION
    Генерує критичні події очищення журналів:
    - Security Log Cleared (1102) - КРИТИЧНИЙ ІНДИКАТОР АТАКИ
    - Event Log Service Shutdown (1100)

.EXAMPLE
    .\07-test-log-clearing.ps1

.NOTES
    Запускати від адміністратора
    УВАГА: Очищає тестовий журнал! НЕ Security log!
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$ClearSecurityLog  # Небезпечний параметр - очистити Security log
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
Write-Host "  Log Clearing Test (1102, 1100)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

Write-Host "УВАГА: Event ID 1102 генерується при очищенні Security журналу!" -ForegroundColor Red
Write-Host "Це КРИТИЧНИЙ індикатор атаки - зловмисники часто очищають логи." -ForegroundColor Red
Write-Host ""

# =============================================================================
# Test 1: Clear Application Log (Safe - generates similar pattern)
# =============================================================================
Write-TestLog "Test 1: Очищення Application журналу (безпечний тест)..." -Status Info

try {
    # Спочатку записуємо тестову подію
    Write-EventLog -LogName Application -Source "Application" -EventId 999 -EntryType Information -Message "Test event before clearing"

    # Очищаємо Application log (це НЕ генерує 1102, але показує механізм)
    wevtutil cl Application
    Write-TestLog "Application log очищено (демонстрація механізму)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 2: Clear Windows PowerShell Log
# =============================================================================
Write-TestLog "Test 2: Очищення Windows PowerShell журналу..." -Status Info

try {
    wevtutil cl "Windows PowerShell"
    Write-TestLog "Windows PowerShell log очищено" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 3: Clear Setup Log
# =============================================================================
Write-TestLog "Test 3: Очищення Setup журналу..." -Status Info

try {
    wevtutil cl Setup
    Write-TestLog "Setup log очищено" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 4: CRITICAL - Clear Security Log (Only with explicit flag)
# =============================================================================
if ($ClearSecurityLog) {
    Write-Host ""
    Write-Host "!!! УВАГА: ОЧИЩЕННЯ SECURITY ЖУРНАЛУ !!!" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "Ви впевнені? Це згенерує Event 1102. (yes/no)"

    if ($confirm -eq 'yes') {
        Write-TestLog "Test 4: Очищення Security журналу (Event 1102)..." -Status Warning

        try {
            wevtutil cl Security
            Write-TestLog "КРИТИЧНО: Security log очищено! Event 1102 згенеровано!" -Status Warning
        } catch {
            Write-TestLog "Помилка очищення Security log: $_" -Status Error
        }
    } else {
        Write-TestLog "Очищення Security log скасовано" -Status Info
    }
} else {
    Write-TestLog "Test 4: Для генерації Event 1102 запустіть з -ClearSecurityLog" -Status Info
    Write-Host ""
    Write-Host "Приклад: .\07-test-log-clearing.ps1 -ClearSecurityLog" -ForegroundColor Yellow
}

# =============================================================================
# Test 5: Simulate Log Tampering Detection Keywords
# =============================================================================
Write-TestLog "Test 5: Симуляція команд очищення логів (для detection)..." -Status Info

# Ці команди записуються в PowerShell логи як підозрілі патерни
$clearCommands = @(
    'wevtutil cl Security',
    'Clear-EventLog -LogName Security',
    'Remove-EventLog',
    '[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog'
)

foreach ($cmd in $clearCommands) {
    Write-TestLog "Logged suspicious pattern: $cmd" -Status Warning
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

# Check for 1102 events
try {
    $count1102 = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 1102 (Audit Log Cleared): $count1102 подій" -ForegroundColor $(if($count1102 -gt 0){'Red'}else{'Green'})
} catch {
    Write-Host "  Event 1102: не знайдено (добре - логи не очищались)" -ForegroundColor Green
}

# Check for 1100 events
try {
    $count1100 = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1100; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 1100 (Event Log Shutdown): $count1100 подій" -ForegroundColor $(if($count1100 -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Host "  Event 1100: не знайдено" -ForegroundColor Green
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_policy"} |= "1102"'
Write-Host '  {job="windows_policy"} |~ "1100|1102"'
Write-Host '  {job="windows_powershell"} |~ "(?i)clear-eventlog|wevtutil.*cl"'
Write-Host ""

Write-Host "MITRE ATT&CK: T1070.001 - Clear Windows Event Logs" -ForegroundColor Cyan
Write-Host "https://attack.mitre.org/techniques/T1070/001/" -ForegroundColor Cyan
Write-Host ""
