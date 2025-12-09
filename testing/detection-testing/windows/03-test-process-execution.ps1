<#
.SYNOPSIS
    Тестування подій виконання процесів (Event 4688, Sysmon Event 1).

.DESCRIPTION
    Генерує події створення процесів для тестування:
    - Process Creation (4688)
    - Sysmon Process Create (Event 1)
    - Підозрілі командні рядки
    - LOLBins (Living Off the Land Binaries)

.EXAMPLE
    .\03-test-process-execution.ps1

.NOTES
    Run as administrator
    Деякі процеси можуть бути заблоковані антивірусом
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
Write-Host "  Process Execution Test (4688, Sysmon 1)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# =============================================================================
# Test 1: Basic Process Creation (4688)
# =============================================================================
Write-TestLog "Test 1: Базове створення процесів..." -Status Info

$basicProcesses = @(
    @{Path = "cmd.exe"; Args = "/c whoami"},
    @{Path = "cmd.exe"; Args = "/c hostname"},
    @{Path = "cmd.exe"; Args = "/c ipconfig"},
    @{Path = "cmd.exe"; Args = "/c net user"}
)

foreach ($proc in $basicProcesses) {
    try {
        Start-Process -FilePath $proc.Path -ArgumentList $proc.Args -WindowStyle Hidden -Wait
        Write-TestLog "Виконано: $($proc.Path) $($proc.Args)" -Status Success
    } catch {
        Write-TestLog "Error: $_" -Status Warning
    }
    Start-Sleep -Milliseconds 500
}

# =============================================================================
# Test 2: PowerShell Execution (4688 + PowerShell logs)
# =============================================================================
Write-TestLog "Test 2: PowerShell виконання..." -Status Info

$psCommands = @(
    'Get-Process | Select-Object -First 5',
    'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 5',
    '[System.Net.Dns]::GetHostAddresses("localhost")'
)

foreach ($cmd in $psCommands) {
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $cmd -WindowStyle Hidden -Wait
        Write-TestLog "PowerShell: $cmd" -Status Success
    } catch {
        Write-TestLog "Error: $_" -Status Warning
    }
    Start-Sleep -Milliseconds 500
}

# =============================================================================
# Test 3: LOLBins (Living Off the Land Binaries)
# =============================================================================
Write-TestLog "Test 3: LOLBins execution..." -Status Info

$lolbins = @(
    # Certutil - часто використовується для завантаження файлів
    @{Path = "certutil.exe"; Args = "-hashfile C:\Windows\System32\cmd.exe MD5"; Name = "Certutil hash"},

    # WMIC - системна інформація
    @{Path = "wmic.exe"; Args = "os get caption"; Name = "WMIC OS info"},

    # Mshta - може виконувати скрипти
    @{Path = "mshta.exe"; Args = "javascript:close()"; Name = "MSHTA"},

    # Regsvr32 - може завантажувати DLL
    @{Path = "regsvr32.exe"; Args = "/s /n /u /i:test.sct scrobj.dll"; Name = "Regsvr32 (will fail)"},

    # Rundll32
    @{Path = "rundll32.exe"; Args = "user32.dll,LockWorkStation"; Name = "Rundll32 (safe)"},

    # Bitsadmin
    @{Path = "bitsadmin.exe"; Args = "/list"; Name = "Bitsadmin list"}
)

foreach ($lol in $lolbins) {
    try {
        Write-TestLog "LOLBin: $($lol.Name)" -Status Info
        $proc = Start-Process -FilePath $lol.Path -ArgumentList $lol.Args -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($proc) {
            Wait-Process -Id $proc.Id -Timeout 5 -ErrorAction SilentlyContinue
            Write-TestLog "Виконано: $($lol.Path)" -Status Success
        }
    } catch {
        Write-TestLog "Помилка або заблоковано: $($lol.Name)" -Status Warning
    }
    Start-Sleep -Milliseconds 500
}

# =============================================================================
# Test 4: Suspicious Command Lines
# =============================================================================
Write-TestLog "Test 4: Підозрілі командні рядки..." -Status Info

$suspiciousCommands = @(
    # Enumeration
    @{Cmd = "cmd.exe /c net localgroup administrators"; Desc = "Admin group enum"},
    @{Cmd = "cmd.exe /c net user /domain"; Desc = "Domain users enum (will fail if not domain)"},
    @{Cmd = "cmd.exe /c net share"; Desc = "Share enumeration"},
    @{Cmd = "cmd.exe /c netstat -ano"; Desc = "Network connections"},
    @{Cmd = "cmd.exe /c tasklist /svc"; Desc = "Process listing"},

    # Reconnaissance
    @{Cmd = "cmd.exe /c systeminfo"; Desc = "System info"},
    @{Cmd = "cmd.exe /c arp -a"; Desc = "ARP table"},
    @{Cmd = "cmd.exe /c route print"; Desc = "Routing table"}
)

foreach ($cmd in $suspiciousCommands) {
    try {
        Write-TestLog "Recon: $($cmd.Desc)" -Status Info
        Invoke-Expression $cmd.Cmd 2>&1 | Out-Null
        Write-TestLog "Виконано: $($cmd.Desc)" -Status Success
    } catch {
        Write-TestLog "Error: $($cmd.Desc)" -Status Warning
    }
    Start-Sleep -Milliseconds 300
}

# =============================================================================
# Test 5: Script Interpreters
# =============================================================================
Write-TestLog "Test 5: Інтерпретатори скриптів..." -Status Info

# VBScript
try {
    $vbsPath = "$env:TEMP\test_vbs.vbs"
    'WScript.Echo "Test VBScript"' | Out-File -FilePath $vbsPath -Encoding ASCII
    Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo", $vbsPath -WindowStyle Hidden -Wait
    Remove-Item $vbsPath -Force -ErrorAction SilentlyContinue
    Write-TestLog "CScript/VBScript виконано" -Status Success
} catch {
    Write-TestLog "Помилка VBScript: $_" -Status Warning
}

# JScript
try {
    $jsPath = "$env:TEMP\test_js.js"
    'WScript.Echo("Test JScript");' | Out-File -FilePath $jsPath -Encoding ASCII
    Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo", $jsPath -WindowStyle Hidden -Wait
    Remove-Item $jsPath -Force -ErrorAction SilentlyContinue
    Write-TestLog "CScript/JScript виконано" -Status Success
} catch {
    Write-TestLog "Помилка JScript: $_" -Status Warning
}

# =============================================================================
# Test 6: Base64 Encoded Commands
# =============================================================================
Write-TestLog "Test 6: Base64 encoded commands..." -Status Info

$plainCommand = 'Write-Host "Base64 Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($plainCommand)
$encodedCommand = [Convert]::ToBase64String($bytes)

try {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $encodedCommand -WindowStyle Hidden -Wait
    Write-TestLog "Base64 команда виконана (SUSPICIOUS!)" -Status Warning
} catch {
    Write-TestLog "Error: $_" -Status Warning
}

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

# Security Log - Event 4688
try {
    $count4688 = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 200 -ErrorAction SilentlyContinue).Count
    Write-Host "  Event 4688 (Process Create): $count4688 подій" -ForegroundColor $(if($count4688 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Event 4688: не знайдено (увімкніть аудит процесів!)" -ForegroundColor Red
}

# Sysmon - Event 1
try {
    $countSysmon1 = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 200 -ErrorAction SilentlyContinue).Count
    Write-Host "  Sysmon Event 1 (Process Create): $countSysmon1 подій" -ForegroundColor $(if($countSysmon1 -gt 0){'Green'}else{'Yellow'})
} catch {
    Write-Host "  Sysmon Event 1: Sysmon не встановлено" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Loki запити для перевірки:" -ForegroundColor Yellow
Write-Host '  {job="windows_process"} |= "cmd.exe"'
Write-Host '  {job="windows_sysmon", event_id="1"} |= "certutil"'
Write-Host '  {job="windows_sysmon"} |~ "(?i)encoded"'
Write-Host ""
