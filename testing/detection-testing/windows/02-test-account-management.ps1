<#
.SYNOPSIS
    Тестування подій управління обліковими записами (Events 4720-4738).

.DESCRIPTION
    Генерує події управління акаунтами:
    - Створення користувача (4720)
    - Зміна акаунту (4738)
    - Додавання до групи (4732)
    - Видалення з групи (4733)
    - Видалення акаунту (4726)

.EXAMPLE
    .\02-test-account-management.ps1

.NOTES
    Запускати від адміністратора
    Створює та видаляє тестові акаунти
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$TestUserPrefix = "TestUser"
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
Write-Host "  Account Management Events Test (4720-4738)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

$testUsers = @()
$testGroup = "TestSecurityGroup"

# =============================================================================
# Test 1: Create User Account (4720)
# =============================================================================
Write-TestLog "Test 1: Створення користувачів (Event 4720)..." -Status Info

for ($i = 1; $i -le 3; $i++) {
    $userName = "${TestUserPrefix}$i"
    $testUsers += $userName

    try {
        $password = ConvertTo-SecureString "TestP@ss$i!" -AsPlainText -Force
        New-LocalUser -Name $userName -Password $password -Description "Test user $i for security monitoring" -ErrorAction Stop | Out-Null
        Write-TestLog "Створено користувача: $userName (Event 4720)" -Status Success
    } catch {
        Write-TestLog "Помилка створення $userName`: $_" -Status Warning
    }
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 2: Create Security Group (4731)
# =============================================================================
Write-TestLog "Test 2: Створення локальної групи (Event 4731)..." -Status Info

try {
    New-LocalGroup -Name $testGroup -Description "Test security group" -ErrorAction Stop | Out-Null
    Write-TestLog "Створено групу: $testGroup (Event 4731)" -Status Success
} catch {
    Write-TestLog "Група вже існує або помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 3: Add User to Group (4732)
# =============================================================================
Write-TestLog "Test 3: Додавання користувачів до групи (Event 4732)..." -Status Info

foreach ($user in $testUsers) {
    try {
        Add-LocalGroupMember -Group $testGroup -Member $user -ErrorAction Stop
        Write-TestLog "Додано $user до $testGroup (Event 4732)" -Status Success
    } catch {
        Write-TestLog "Помилка додавання $user`: $_" -Status Warning
    }
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 4: Add User to Administrators (High Risk - 4732)
# =============================================================================
Write-TestLog "Test 4: Додавання до групи Administrators (Event 4732 - HIGH RISK)..." -Status Info

try {
    Add-LocalGroupMember -Group "Administrators" -Member $testUsers[0] -ErrorAction Stop
    Write-TestLog "КРИТИЧНО: $($testUsers[0]) додано до Administrators!" -Status Warning
} catch {
    Write-TestLog "Користувач вже в групі або помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 5: Modify User Account (4738)
# =============================================================================
Write-TestLog "Test 5: Зміна параметрів користувача (Event 4738)..." -Status Info

try {
    # Зміна опису
    Set-LocalUser -Name $testUsers[0] -Description "Modified test user" -ErrorAction Stop
    Write-TestLog "Змінено опис користувача $($testUsers[0]) (Event 4738)" -Status Success
} catch {
    Write-TestLog "Помилка зміни: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 6: Enable/Disable User (4722, 4725)
# =============================================================================
Write-TestLog "Test 6: Вимкнення/увімкнення акаунту (Events 4722, 4725)..." -Status Info

try {
    Disable-LocalUser -Name $testUsers[1] -ErrorAction Stop
    Write-TestLog "Вимкнено $($testUsers[1]) (Event 4725)" -Status Success

    Start-Sleep -Seconds 1

    Enable-LocalUser -Name $testUsers[1] -ErrorAction Stop
    Write-TestLog "Увімкнено $($testUsers[1]) (Event 4722)" -Status Success
} catch {
    Write-TestLog "Помилка: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 7: Password Reset (4724)
# =============================================================================
Write-TestLog "Test 7: Скидання пароля (Event 4724)..." -Status Info

try {
    $newPassword = ConvertTo-SecureString "NewP@ssw0rd!" -AsPlainText -Force
    Set-LocalUser -Name $testUsers[2] -Password $newPassword -ErrorAction Stop
    Write-TestLog "Скинуто пароль для $($testUsers[2]) (Event 4724)" -Status Success
} catch {
    Write-TestLog "Помилка скидання пароля: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 8: Remove User from Admin Group (4733)
# =============================================================================
Write-TestLog "Test 8: Видалення з групи Administrators (Event 4733)..." -Status Info

try {
    Remove-LocalGroupMember -Group "Administrators" -Member $testUsers[0] -ErrorAction Stop
    Write-TestLog "Видалено $($testUsers[0]) з Administrators (Event 4733)" -Status Success
} catch {
    Write-TestLog "Помилка видалення: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Cleanup
# =============================================================================
Write-TestLog "Очистка тестових даних..." -Status Info

# Видалення користувачів з групи
foreach ($user in $testUsers) {
    try {
        Remove-LocalGroupMember -Group $testGroup -Member $user -ErrorAction SilentlyContinue
    } catch {}
}

# Видалення групи (4734)
try {
    Remove-LocalGroup -Name $testGroup -ErrorAction SilentlyContinue
    Write-TestLog "Видалено групу $testGroup (Event 4734)" -Status Success
} catch {
    Write-TestLog "Група не існує" -Status Warning
}

# Видалення користувачів (4726)
foreach ($user in $testUsers) {
    try {
        Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
        Write-TestLog "Видалено користувача $user (Event 4726)" -Status Success
    } catch {
        Write-TestLog "Користувач $user не існує" -Status Warning
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

$events = @(
    @{Id = 4720; Name = "User Created"},
    @{Id = 4722; Name = "User Enabled"},
    @{Id = 4724; Name = "Password Reset"},
    @{Id = 4725; Name = "User Disabled"},
    @{Id = 4726; Name = "User Deleted"},
    @{Id = 4731; Name = "Group Created"},
    @{Id = 4732; Name = "Member Added to Group"},
    @{Id = 4733; Name = "Member Removed from Group"},
    @{Id = 4734; Name = "Group Deleted"},
    @{Id = 4738; Name = "User Changed"}
)

foreach ($event in $events) {
    try {
        $count = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$event.Id; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
        Write-Host "  Event $($event.Id) ($($event.Name)): $count подій" -ForegroundColor $(if($count -gt 0){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  Event $($event.Id): не знайдено" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_accounts"} |~ "4720|4732"'
Write-Host '  {job="windows_accounts"} |= "Administrators"'
Write-Host ""
