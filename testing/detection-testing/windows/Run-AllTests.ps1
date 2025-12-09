<#
.SYNOPSIS
    Запуск всіх тестів виявлення для Windows.

.DESCRIPTION
    Послідовно виконує всі тестові скрипти для генерації
    подій безпеки та перевірки системи моніторингу.

.PARAMETER DelaySeconds
    Затримка між тестами (за замовчуванням 10 секунд)

.PARAMETER SkipTests
    Масив номерів тестів для пропуску (e.g.: 1,3,5)

.EXAMPLE
    .\Run-AllTests.ps1

.EXAMPLE
    .\Run-AllTests.ps1 -DelaySeconds 30

.EXAMPLE
    .\Run-AllTests.ps1 -SkipTests 4,5

.NOTES
    Run as administrator
    Тільки для тестового середовища!
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]$DelaySeconds = 10,
    [int[]]$SkipTests = @()
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Banner {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-TestHeader {
    param([int]$Number, [string]$Name)
    Write-Host ""
    Write-Host ("*" * 60) -ForegroundColor Magenta
    Write-Host "  TEST $Number`: $Name" -ForegroundColor Magenta
    Write-Host ("*" * 60) -ForegroundColor Magenta
    Write-Host ""
}

# =============================================================================
# Warning Banner
# =============================================================================
Clear-Host
Write-Banner "Windows Security Detection Testing Suite"

Write-Host @"
 ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
 ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
 ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
"@ -ForegroundColor Yellow

Write-Host ""
Write-Host "УВАГА!" -ForegroundColor Red -BackgroundColor Yellow
Write-Host @"
Ці тести призначені ТІЛЬКИ для тестового середовища!

Тести генерують події, які можуть:
- Тригерити алерти в SIEM системах
- Бути заблоковані антивірусом
- Створювати тимчасові акаунти та сервіси
- Виконувати підозрілі команди

НЕ запускайте на production системах!
"@ -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Продовжити виконання тестів? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Скасовано користувачем" -ForegroundColor Yellow
    exit 0
}

# =============================================================================
# Test Scripts
# =============================================================================
$testScripts = @(
    @{Number = 1; Name = "Authentication Events"; Script = "01-test-authentication.ps1"},
    @{Number = 2; Name = "Account Management"; Script = "02-test-account-management.ps1"},
    @{Number = 3; Name = "Process Execution"; Script = "03-test-process-execution.ps1"},
    @{Number = 4; Name = "PowerShell Events"; Script = "04-test-powershell.ps1"},
    @{Number = 5; Name = "Service Creation"; Script = "05-test-service-creation.ps1"},
    @{Number = 6; Name = "Scheduled Tasks"; Script = "06-test-scheduled-tasks.ps1"},
    @{Number = 7; Name = "Log Clearing (1102)"; Script = "07-test-log-clearing.ps1"},
    @{Number = 8; Name = "Active Directory (5136-5141)"; Script = "08-test-active-directory.ps1"}
)

$startTime = Get-Date
$passedTests = 0
$failedTests = 0
$skippedTests = 0

Write-Banner "Starting Test Suite"
Write-Host "Host: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "User: $env:USERNAME" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Tests to run: $($testScripts.Count - $SkipTests.Count)" -ForegroundColor Cyan
Write-Host "Delay between tests: $DelaySeconds seconds" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Run Tests
# =============================================================================
foreach ($test in $testScripts) {
    if ($SkipTests -contains $test.Number) {
        Write-Host "[SKIP] Test $($test.Number): $($test.Name)" -ForegroundColor Yellow
        $skippedTests++
        continue
    }

    Write-TestHeader -Number $test.Number -Name $test.Name

    $scriptPath = Join-Path $ScriptDir $test.Script

    if (Test-Path $scriptPath) {
        try {
            & $scriptPath
            $passedTests++
            Write-Host ""
            Write-Host "[DONE] Test $($test.Number) completed" -ForegroundColor Green
        } catch {
            $failedTests++
            Write-Host "[FAIL] Test $($test.Number) failed: $_" -ForegroundColor Red
        }
    } else {
        $failedTests++
        Write-Host "[ERROR] Script not found: $scriptPath" -ForegroundColor Red
    }

    if ($test.Number -lt $testScripts[-1].Number) {
        Write-Host ""
        Write-Host "Waiting $DelaySeconds seconds before next test..." -ForegroundColor Gray
        Start-Sleep -Seconds $DelaySeconds
    }
}

# =============================================================================
# Summary
# =============================================================================
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Banner "Test Suite Complete!"

Write-Host "Results:" -ForegroundColor Cyan
Write-Host "  Passed:  $passedTests" -ForegroundColor Green
Write-Host "  Failed:  $failedTests" -ForegroundColor $(if($failedTests -gt 0){'Red'}else{'Green'})
Write-Host "  Skipped: $skippedTests" -ForegroundColor Yellow
Write-Host ""
Write-Host "Duration: $($duration.Minutes) min $($duration.Seconds) sec" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Event Summary
# =============================================================================
Write-Host "Event Summary (last 10 minutes):" -ForegroundColor Yellow
Write-Host ""

$eventSummary = @(
    @{Log = "Security"; Id = 4624; Name = "Successful Logon"},
    @{Log = "Security"; Id = 4625; Name = "Failed Logon"},
    @{Log = "Security"; Id = 4720; Name = "User Created"},
    @{Log = "Security"; Id = 4732; Name = "Member Added to Group"},
    @{Log = "Security"; Id = 4688; Name = "Process Created"},
    @{Log = "Security"; Id = 4698; Name = "Task Created"},
    @{Log = "Security"; Id = 4697; Name = "Service Installed"},
    @{Log = "Security"; Id = 1102; Name = "Audit Log Cleared"},
    @{Log = "Security"; Id = 5136; Name = "AD Object Modified"},
    @{Log = "Security"; Id = 5137; Name = "AD Object Created"},
    @{Log = "Security"; Id = 5141; Name = "AD Object Deleted"},
    @{Log = "System"; Id = 7045; Name = "New Service"},
    @{Log = "Microsoft-Windows-PowerShell/Operational"; Id = 4104; Name = "PowerShell Script Block"},
    @{Log = "Microsoft-Windows-Sysmon/Operational"; Id = 1; Name = "Sysmon Process"}
)

foreach ($evt in $eventSummary) {
    try {
        $count = (Get-WinEvent -FilterHashtable @{LogName=$evt.Log; Id=$evt.Id; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 500 -ErrorAction SilentlyContinue).Count
        $color = if ($count -gt 0) { 'Green' } else { 'DarkGray' }
        Write-Host "  Event $($evt.Id) ($($evt.Name)): $count" -ForegroundColor $color
    } catch {
        Write-Host "  Event $($evt.Id) ($($evt.Name)): N/A" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Grafana Verification:" -ForegroundColor Yellow
Write-Host @"
1. Open Grafana: http://<monitoring-server>:3000
2. Go to Explore -> Loki
3. Run queries:

   # All events from this host
   {host="$env:COMPUTERNAME"}

   # Authentication failures
   {job="windows_auth"} |= "4625"

   # Account changes
   {job="windows_accounts"} |~ "4720|4732"

   # New services
   {job="windows_services"} |= "7045"

   # PowerShell events
   {job="windows_powershell"} |~ "invoke-|download"
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "Test suite finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host ""
