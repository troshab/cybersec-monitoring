<#
.SYNOPSIS
    Тестування подій PowerShell (Events 4103, 4104).

.DESCRIPTION
    Генерує події PowerShell Script Block Logging:
    - Звичайні команди
    - Підозрілі патерни (Invoke-*, Download*, Bypass)
    - Encoded commands
    - AMSI bypass attempts

.EXAMPLE
    .\04-test-powershell.ps1

.NOTES
    Запускати від адміністратора
    Антивірус може заблокувати деякі тести
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
Write-Host "  PowerShell Events Test (4103, 4104)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# =============================================================================
# Test 1: Normal PowerShell Commands
# =============================================================================
Write-TestLog "Test 1: Звичайні PowerShell команди..." -Status Info

# Ці команди генерують події 4103/4104
Get-Process | Select-Object -First 3 | Out-Null
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 3 | Out-Null
Get-ChildItem $env:TEMP | Select-Object -First 3 | Out-Null

Write-TestLog "Базові команди виконано" -Status Success

# =============================================================================
# Test 2: Suspicious Keywords (Trigger alerts)
# =============================================================================
Write-TestLog "Test 2: Команди з підозрілими ключовими словами..." -Status Info

# Invoke-Expression (часто використовується для виконання коду)
$testCode = 'Write-Host "Invoke-Expression test"'
try {
    Invoke-Expression $testCode
    Write-TestLog "Invoke-Expression виконано" -Status Warning
} catch {
    Write-TestLog "Invoke-Expression заблоковано" -Status Info
}

# Invoke-Command (remote execution)
try {
    Invoke-Command -ScriptBlock { Get-Date } -ComputerName localhost -ErrorAction SilentlyContinue
    Write-TestLog "Invoke-Command виконано" -Status Warning
} catch {
    Write-TestLog "Invoke-Command потребує WinRM" -Status Info
}

# =============================================================================
# Test 3: Download Patterns
# =============================================================================
Write-TestLog "Test 3: Патерни завантаження (Download)..." -Status Info

# Net.WebClient (класичний патерн)
try {
    $webClient = New-Object System.Net.WebClient
    # Не завантажуємо реально, просто створюємо об'єкт
    Write-TestLog "System.Net.WebClient створено" -Status Warning
} catch {
    Write-TestLog "WebClient заблоковано" -Status Info
}

# DownloadString pattern (не виконуємо реально)
$downloadPatterns = @(
    '# $wc = New-Object Net.WebClient; $wc.DownloadString("http://example.com")',
    '# Invoke-WebRequest -Uri "http://example.com"',
    '# (New-Object Net.WebClient).DownloadFile("http://example.com","C:\temp\file.exe")'
)

foreach ($pattern in $downloadPatterns) {
    Write-TestLog "Патерн записано в логи: $pattern" -Status Info
}

# =============================================================================
# Test 4: Encoded Commands
# =============================================================================
Write-TestLog "Test 4: Base64 encoded команди..." -Status Info

$commands = @(
    'Get-Date',
    'Get-Process',
    'Write-Host "Encoded test"'
)

foreach ($cmd in $commands) {
    try {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
        $encoded = [Convert]::ToBase64String($bytes)

        # Виконання через -EncodedCommand генерує логи
        $result = powershell -NoProfile -EncodedCommand $encoded 2>&1
        Write-TestLog "Encoded: $cmd" -Status Warning
    } catch {
        Write-TestLog "Помилка encoded: $_" -Status Warning
    }
}

# =============================================================================
# Test 5: Bypass Keywords
# =============================================================================
Write-TestLog "Test 5: Bypass патерни..." -Status Info

# ExecutionPolicy bypass (безпечний приклад)
try {
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'Bypass test'" 2>&1 | Out-Null
    Write-TestLog "ExecutionPolicy Bypass виконано" -Status Warning
} catch {
    Write-TestLog "Bypass заблоковано" -Status Info
}

# Hidden window
try {
    Start-Process powershell -WindowStyle Hidden -ArgumentList "-Command", "Get-Date" -Wait
    Write-TestLog "Hidden window виконано" -Status Warning
} catch {
    Write-TestLog "Hidden window заблоковано" -Status Info
}

# =============================================================================
# Test 6: Reflection/Assembly Loading
# =============================================================================
Write-TestLog "Test 6: Reflection патерни..." -Status Info

try {
    # Завантаження стандартної збірки (безпечно)
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    Write-TestLog "Assembly loading виконано" -Status Warning
} catch {
    Write-TestLog "Assembly loading заблоковано" -Status Info
}

# =============================================================================
# Test 7: Script Block Logging Patterns
# =============================================================================
Write-TestLog "Test 7: Патерни для Script Block Logging..." -Status Info

# Heredoc (multi-line script block)
$scriptBlock = @'
# This is a multi-line script block
# That will be logged by Script Block Logging
$processes = Get-Process
$services = Get-Service
Write-Output "Script block test completed"
'@

try {
    Invoke-Expression $scriptBlock | Out-Null
    Write-TestLog "Script Block виконано (4104)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 8: Module Logging (4103)
# =============================================================================
Write-TestLog "Test 8: Module Logging (4103)..." -Status Info

try {
    # Використання модулів генерує 4103
    Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
    Get-ChildItem $env:TEMP -ErrorAction SilentlyContinue | Out-Null
    Write-TestLog "Module команди виконано (4103)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Test 9: Suspicious String Patterns
# =============================================================================
Write-TestLog "Test 9: Підозрілі рядкові патерни..." -Status Info

# Ці рядки мають тригерити алерти в SIEM
$suspiciousStrings = @(
    # Mimikatz patterns (тільки рядки, не виконуються)
    '"sekurlsa::logonpasswords"',
    '"Invoke-Mimikatz"',

    # Empire/Covenant patterns
    '"Invoke-Empire"',
    '"Invoke-BloodHound"',

    # Common attack patterns
    '"IEX (New-Object Net.WebClient)"',
    '"powershell -ep bypass"',
    '"-nop -w hidden"'
)

foreach ($str in $suspiciousStrings) {
    Write-TestLog "Suspicious string logged: $str" -Status Warning
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

# PowerShell Operational Log
try {
    $count4103 = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 500 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 4103 (Module Logging): $count4103 подій" -ForegroundColor $(if($count4103 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 4103: PowerShell logging не увімкнено" -ForegroundColor Red
}

try {
    $count4104 = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 500 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 4104 (Script Block): $count4104 подій" -ForegroundColor $(if($count4104 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 4104: Script Block logging не увімкнено" -ForegroundColor Red
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_powershell"}'
Write-Host '  {job="windows_powershell"} |~ "(?i)invoke-|download|bypass|encoded"'
Write-Host '  {job="windows_powershell"} |= "mimikatz"'
Write-Host ""
