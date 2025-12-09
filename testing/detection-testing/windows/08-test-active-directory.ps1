<#
.SYNOPSIS
    Тестування подій Active Directory (Events 5136-5141).

.DESCRIPTION
    Генерує події змін в Active Directory:
    - Directory Object Modified (5136)
    - Directory Object Created (5137)
    - Directory Object Undeleted (5138)
    - Directory Object Moved (5139)
    - Directory Object Deleted (5141)

.EXAMPLE
    .\08-test-active-directory.ps1

.NOTES
    ЗАПУСКАТИ ТІЛЬКИ НА КОНТРОЛЕРІ ДОМЕНУ!
    Run as administrator домену
    Тестові об'єкти автоматично видаляються
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$TestOUName = "TestSecurityOU",
    [string]$TestUserName = "TestADUser",
    [string]$TestGroupName = "TestADGroup"
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
Write-Host "  Active Directory Events Test (5136-5141)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# =============================================================================
# Check if running on Domain Controller
# =============================================================================
Write-TestLog "Verification середовища..." -Status Info

$isDC = $false
try {
    $dcInfo = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
    $isDC = $true
    Write-TestLog "Запущено на контролері домену: $($dcInfo.Name)" -Status Success
    Write-TestLog "Домен: $($dcInfo.Domain)" -Status Info
} catch {
    Write-TestLog "УВАГА: Цей скрипт призначений для контролера домену!" -Status Error
    Write-Host ""
    Write-Host "Для тестування на робочій станції використовуйте:" -ForegroundColor Yellow
    Write-Host "  - 02-test-account-management.ps1 (локальні користувачі)" -ForegroundColor Yellow
    Write-Host ""

    $continue = Read-Host "Продовжити без AD тестів? (y/n)"
    if ($continue -ne 'y') {
        exit 0
    }
}

if (-not $isDC) {
    Write-TestLog "Пропуск AD тестів (не DC)" -Status Warning
    exit 0
}

# Get domain DN
$domainDN = (Get-ADDomain).DistinguishedName
$testOUPath = "OU=$TestOUName,$domainDN"

# =============================================================================
# Test 1: Create Organizational Unit (5137)
# =============================================================================
Write-TestLog "Test 1: Створення OU (Event 5137)..." -Status Info

try {
    # Видалення if exists
    Get-ADOrganizationalUnit -Identity $testOUPath -ErrorAction SilentlyContinue |
        Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru |
        Remove-ADOrganizationalUnit -Confirm:$false -ErrorAction SilentlyContinue

    # Створення нового OU
    New-ADOrganizationalUnit -Name $TestOUName -Path $domainDN -Description "Test OU for security monitoring" -ErrorAction Stop
    Write-TestLog "OU '$TestOUName' створено (Event 5137)" -Status Success
} catch {
    Write-TestLog "Помилка створення OU: $_" -Status Error
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 2: Create AD User (5137)
# =============================================================================
Write-TestLog "Test 2: Створення користувача AD (Event 5137)..." -Status Info

try {
    $userPassword = ConvertTo-SecureString "TestP@ssw0rd123!" -AsPlainText -Force

    New-ADUser -Name $TestUserName `
        -SamAccountName $TestUserName `
        -UserPrincipalName "$TestUserName@$((Get-ADDomain).DNSRoot)" `
        -Path $testOUPath `
        -AccountPassword $userPassword `
        -Enabled $true `
        -Description "Test user for security monitoring" `
        -ErrorAction Stop

    Write-TestLog "Користувач '$TestUserName' створено (Event 5137)" -Status Success
} catch {
    Write-TestLog "Помилка створення користувача: $_" -Status Warning
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 3: Create AD Group (5137)
# =============================================================================
Write-TestLog "Test 3: Створення групи AD (Event 5137)..." -Status Info

try {
    New-ADGroup -Name $TestGroupName `
        -SamAccountName $TestGroupName `
        -GroupCategory Security `
        -GroupScope Global `
        -Path $testOUPath `
        -Description "Test group for security monitoring" `
        -ErrorAction Stop

    Write-TestLog "Група '$TestGroupName' створено (Event 5137)" -Status Success
} catch {
    Write-TestLog "Помилка створення групи: $_" -Status Warning
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 4: Modify AD User (5136)
# =============================================================================
Write-TestLog "Test 4: Зміна атрибутів користувача (Event 5136)..." -Status Info

try {
    Set-ADUser -Identity $TestUserName `
        -Description "Modified test user - security alert should trigger" `
        -Office "Test Office" `
        -Title "Test Title" `
        -ErrorAction Stop

    Write-TestLog "Атрибути користувача змінено (Event 5136)" -Status Success
} catch {
    Write-TestLog "Помилка зміни користувача: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 5: Add User to Group (5136)
# =============================================================================
Write-TestLog "Test 5: Додавання до групи (Event 5136)..." -Status Info

try {
    Add-ADGroupMember -Identity $TestGroupName -Members $TestUserName -ErrorAction Stop
    Write-TestLog "Користувач доданий до групи (Event 5136)" -Status Success
} catch {
    Write-TestLog "Error: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 6: Add User to Domain Admins (CRITICAL - 5136)
# =============================================================================
Write-TestLog "Test 6: Додавання до Domain Admins (CRITICAL - Event 5136)..." -Status Info

try {
    Add-ADGroupMember -Identity "Domain Admins" -Members $TestUserName -ErrorAction Stop
    Write-TestLog "КРИТИЧНО: Користувач доданий до Domain Admins!" -Status Warning
} catch {
    Write-TestLog "Помилка додавання до Domain Admins: $_" -Status Warning
}

Start-Sleep -Seconds 2

# =============================================================================
# Test 7: Remove from Domain Admins (5136)
# =============================================================================
Write-TestLog "Test 7: Видалення з Domain Admins (Event 5136)..." -Status Info

try {
    Remove-ADGroupMember -Identity "Domain Admins" -Members $TestUserName -Confirm:$false -ErrorAction Stop
    Write-TestLog "Користувач видалений з Domain Admins (Event 5136)" -Status Success
} catch {
    Write-TestLog "Error: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 8: Modify Group (5136)
# =============================================================================
Write-TestLog "Test 8: Зміна групи (Event 5136)..." -Status Info

try {
    Set-ADGroup -Identity $TestGroupName -Description "Modified group description" -ErrorAction Stop
    Write-TestLog "Група змінена (Event 5136)" -Status Success
} catch {
    Write-TestLog "Error: $_" -Status Warning
}

Start-Sleep -Seconds 1

# =============================================================================
# Test 9: Move Object (5139)
# =============================================================================
Write-TestLog "Test 9: Переміщення об'єкта (Event 5139)..." -Status Info

try {
    # Створення другого OU для переміщення
    $testOU2 = "OU=TestOU2,$domainDN"
    New-ADOrganizationalUnit -Name "TestOU2" -Path $domainDN -ErrorAction SilentlyContinue

    # Переміщення користувача
    Move-ADObject -Identity "CN=$TestUserName,$testOUPath" -TargetPath $testOU2 -ErrorAction Stop
    Write-TestLog "Об'єкт переміщено (Event 5139)" -Status Success

    # Повернення назад
    Start-Sleep -Seconds 1
    Move-ADObject -Identity "CN=$TestUserName,$testOU2" -TargetPath $testOUPath -ErrorAction Stop
    Write-TestLog "Об'єкт повернено назад" -Status Info
} catch {
    Write-TestLog "Помилка переміщення: $_" -Status Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Write-TestLog "Cleanup тестових об'єктів..." -Status Info

Start-Sleep -Seconds 2

try {
    # Видалення користувача (5141)
    Remove-ADUser -Identity $TestUserName -Confirm:$false -ErrorAction SilentlyContinue
    Write-TestLog "Користувач видалено (Event 5141)" -Status Success
} catch {
    Write-TestLog "Користувач не існує" -Status Warning
}

try {
    # Видалення групи (5141)
    Remove-ADGroup -Identity $TestGroupName -Confirm:$false -ErrorAction SilentlyContinue
    Write-TestLog "Група видалена (Event 5141)" -Status Success
} catch {
    Write-TestLog "Група не існує" -Status Warning
}

try {
    # Видалення OU (5141)
    Get-ADOrganizationalUnit -Identity $testOUPath -ErrorAction SilentlyContinue |
        Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru |
        Remove-ADOrganizationalUnit -Confirm:$false -ErrorAction SilentlyContinue
    Write-TestLog "OU видалено (Event 5141)" -Status Success
} catch {
    Write-TestLog "OU не існує" -Status Warning
}

try {
    # Видалення другого OU
    Get-ADOrganizationalUnit -Identity "OU=TestOU2,$domainDN" -ErrorAction SilentlyContinue |
        Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru |
        Remove-ADOrganizationalUnit -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

# =============================================================================
# Verification
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Тест завершено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Verification подій:" -ForegroundColor Cyan
Write-Host ""

$events = @(
    @{Id = 5136; Name = "Directory Object Modified"},
    @{Id = 5137; Name = "Directory Object Created"},
    @{Id = 5138; Name = "Directory Object Undeleted"},
    @{Id = 5139; Name = "Directory Object Moved"},
    @{Id = 5141; Name = "Directory Object Deleted"}
)

foreach ($event in $events) {
    try {
        $count = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$event.Id; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
        Write-Host "  Event $($event.Id) ($($event.Name)): $count подій" -ForegroundColor $(if($count -gt 0){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  Event $($event.Id): не знайдено (потребує DS аудиту)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_directory_service"} |~ "5136|5137|5141"'
Write-Host '  {job="windows_directory_service"} |= "Domain Admins"'
Write-Host '  {job="windows_accounts"} |= "TestADUser"'
Write-Host ""

Write-Host "Якщо події не з'являються, перевірте AD DS аудит:" -ForegroundColor Cyan
Write-Host "  gpmc.msc -> Default Domain Controllers Policy ->" -ForegroundColor Cyan
Write-Host "  Computer Configuration -> Policies -> Windows Settings ->" -ForegroundColor Cyan
Write-Host "  Security Settings -> Advanced Audit Policy -> DS Access" -ForegroundColor Cyan
Write-Host ""
