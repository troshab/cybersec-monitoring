<#
.SYNOPSIS
    Тестування подій Scheduled Tasks (Events 4698-4702).

.DESCRIPTION
    Генерує події планувальника завдань:
    - Task Created (4698)
    - Task Deleted (4699)
    - Task Enabled (4700)
    - Task Disabled (4701)
    - Task Updated (4702)

.EXAMPLE
    .\06-test-scheduled-tasks.ps1

.NOTES
    Запускати від адміністратора
    Завдання автоматично видаляються після тесту
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
Write-Host "  Scheduled Tasks Test (4698-4702)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

$taskName1 = "TestSecurityTask1"
$taskName2 = "TestSecurityTask2"
$taskPath = "\SecurityTests\"

# =============================================================================
# Cleanup existing test tasks
# =============================================================================
Write-TestLog "Очистка існуючих тестових завдань..." -Status Info

Unregister-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName2 -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue

# =============================================================================
# Test 1: Create Scheduled Task (4698)
# =============================================================================
Write-TestLog "Test 1: Створення Scheduled Task (Event 4698)..." -Status Info

try {
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test Task 1"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Description "Test security task" -ErrorAction Stop | Out-Null

    Write-TestLog "Завдання $taskName1 створено (Event 4698)" -Status Success
} catch {
    Write-TestLog "Помилка створення: $_" -Status Error
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 2: Create Suspicious Task (PowerShell)
# =============================================================================
Write-TestLog "Test 2: Створення підозрілого завдання з PowerShell..." -Status Info

try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command Get-Process"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName2 -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Description "Suspicious PS task" -ErrorAction Stop | Out-Null

    Write-TestLog "Підозріле завдання $taskName2 створено (SUSPICIOUS!)" -Status Warning
} catch {
    Write-TestLog "Помилка: $_" -Status Error
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 3: Disable Task (4701)
# =============================================================================
Write-TestLog "Test 3: Вимкнення завдання (Event 4701)..." -Status Info

try {
    Disable-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath -ErrorAction Stop | Out-Null
    Write-TestLog "Завдання $taskName1 вимкнено (Event 4701)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 4: Enable Task (4700)
# =============================================================================
Write-TestLog "Test 4: Увімкнення завдання (Event 4700)..." -Status Info

try {
    Enable-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath -ErrorAction Stop | Out-Null
    Write-TestLog "Завдання $taskName1 увімкнено (Event 4700)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 5: Update Task (4702)
# =============================================================================
Write-TestLog "Test 5: Оновлення завдання (Event 4702)..." -Status Info

try {
    $task = Get-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath
    $task.Description = "Updated test security task"
    Set-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
    Write-TestLog "Завдання $taskName1 оновлено (Event 4702)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 6: Create Task via schtasks.exe
# =============================================================================
Write-TestLog "Test 6: Створення через schtasks.exe..." -Status Info

$schtaskName = "TestSchtaskCmd"
try {
    schtasks /delete /tn $schtaskName /f 2>&1 | Out-Null
    schtasks /create /tn $schtaskName /tr "cmd.exe /c echo schtasks test" /sc once /st 23:59 /ru SYSTEM 2>&1 | Out-Null
    Write-TestLog "Завдання $schtaskName створено через schtasks.exe" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Write-TestLog "Очистка тестових завдань..." -Status Info

try {
    Unregister-ScheduledTask -TaskName $taskName1 -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
    Write-TestLog "Видалено $taskName1 (Event 4699)" -Status Success
} catch {}

try {
    Unregister-ScheduledTask -TaskName $taskName2 -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
    Write-TestLog "Видалено $taskName2 (Event 4699)" -Status Success
} catch {}

try {
    schtasks /delete /tn $schtaskName /f 2>&1 | Out-Null
    Write-TestLog "Видалено $schtaskName" -Status Success
} catch {}

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

$events = @(
    @{Id = 4698; Name = "Task Created"},
    @{Id = 4699; Name = "Task Deleted"},
    @{Id = 4700; Name = "Task Enabled"},
    @{Id = 4701; Name = "Task Disabled"},
    @{Id = 4702; Name = "Task Updated"}
)

foreach ($event in $events) {
    try {
        $count = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$event.Id; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
        Write-Host "  Event $($event.Id) ($($event.Name)): $count подій" -ForegroundColor $(if($count -gt 0){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  Event $($event.Id): не знайдено (потребує аудиту)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_persistence"} |~ "4698|4699"'
Write-Host '  {job="windows_persistence"} |= "TestSecurityTask"'
Write-Host ""
