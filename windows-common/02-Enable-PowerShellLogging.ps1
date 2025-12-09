<#
.SYNOPSIS
    Включення повного логування PowerShell.

.DESCRIPTION
    Налаштовує Script Block Logging, Module Logging та опціонально Transcription
    для детального відстеження всіх PowerShell команд.

    Критично важливо для виявлення:
    - Encoded PowerShell команд
    - Download cradles (IEX, Invoke-WebRequest)
    - Malware та lateral movement

.PARAMETER EnableTranscription
    Включити запис всіх PowerShell сесій у файли (генерує багато даних)

.PARAMETER TranscriptPath
    Шлях для збереження transcript файлів

.EXAMPLE
    .\02-Enable-PowerShellLogging.ps1
    Включає Script Block та Module logging

.EXAMPLE
    .\02-Enable-PowerShellLogging.ps1 -EnableTranscription -TranscriptPath "C:\PSLogs"
    Включає також Transcription

.NOTES
    Event IDs: 4103 (Module Logging), 4104 (Script Block Logging)
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$EnableTranscription,
    [string]$TranscriptPath = "C:\PSTranscripts"
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $colors = @{
        'Info'    = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }

    $prefix = @{
        'Info'    = '[*]'
        'Success' = '[+]'
        'Warning' = '[!]'
        'Error'   = '[-]'
    }

    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PowerShell Logging Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Script Block Logging (Event ID 4104)
# =============================================================================
Write-Log "Налаштування Script Block Logging..." -Level Info

# 64-bit
$regPath64 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $regPath64)) {
    New-Item -Path $regPath64 -Force | Out-Null
}
Set-ItemProperty -Path $regPath64 -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath64 -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

# 32-bit (Wow6432Node)
$regPath32 = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $regPath32)) {
    New-Item -Path $regPath32 -Force | Out-Null
}
Set-ItemProperty -Path $regPath32 -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath32 -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

Write-Log "Script Block Logging включено" -Level Success

# =============================================================================
# Module Logging (Event ID 4103)
# =============================================================================
Write-Log "Налаштування Module Logging..." -Level Info

# 64-bit
$modPath64 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modPath64)) {
    New-Item -Path $modPath64 -Force | Out-Null
}
Set-ItemProperty -Path $modPath64 -Name "EnableModuleLogging" -Value 1 -Type DWord

# Module Names (логувати всі модулі)
$modNamesPath64 = "$modPath64\ModuleNames"
if (-not (Test-Path $modNamesPath64)) {
    New-Item -Path $modNamesPath64 -Force | Out-Null
}
Set-ItemProperty -Path $modNamesPath64 -Name "*" -Value "*" -Type String

# 32-bit
$modPath32 = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modPath32)) {
    New-Item -Path $modPath32 -Force | Out-Null
}
Set-ItemProperty -Path $modPath32 -Name "EnableModuleLogging" -Value 1 -Type DWord

$modNamesPath32 = "$modPath32\ModuleNames"
if (-not (Test-Path $modNamesPath32)) {
    New-Item -Path $modNamesPath32 -Force | Out-Null
}
Set-ItemProperty -Path $modNamesPath32 -Name "*" -Value "*" -Type String

Write-Log "Module Logging включено" -Level Success

# =============================================================================
# Transcription (опціонально)
# =============================================================================
if ($EnableTranscription) {
    Write-Log "Налаштування Transcription..." -Level Info

    # Створення директорії для логів
    if (-not (Test-Path $TranscriptPath)) {
        New-Item -ItemType Directory -Path $TranscriptPath -Force | Out-Null
    }

    # Права доступу (тільки адміни можуть читати)
    $acl = Get-Acl $TranscriptPath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $TranscriptPath $acl

    # 64-bit
    $transPath64 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $transPath64)) {
        New-Item -Path $transPath64 -Force | Out-Null
    }
    Set-ItemProperty -Path $transPath64 -Name "EnableTranscripting" -Value 1 -Type DWord
    Set-ItemProperty -Path $transPath64 -Name "OutputDirectory" -Value $TranscriptPath -Type String
    Set-ItemProperty -Path $transPath64 -Name "EnableInvocationHeader" -Value 1 -Type DWord

    # 32-bit
    $transPath32 = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $transPath32)) {
        New-Item -Path $transPath32 -Force | Out-Null
    }
    Set-ItemProperty -Path $transPath32 -Name "EnableTranscripting" -Value 1 -Type DWord
    Set-ItemProperty -Path $transPath32 -Name "OutputDirectory" -Value $TranscriptPath -Type String
    Set-ItemProperty -Path $transPath32 -Name "EnableInvocationHeader" -Value 1 -Type DWord

    Write-Log "Transcription включено. Логи: $TranscriptPath" -Level Success
} else {
    Write-Log "Transcription пропущено (використовуйте -EnableTranscription для включення)" -Level Warning
}

# =============================================================================
# Event Log Size
# =============================================================================
Write-Log "Збільшення розміру PowerShell Event Log..." -Level Info

wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
wevtutil sl "Windows PowerShell" /ms:134217728

Write-Log "Розмір логу: 256MB" -Level Success

# =============================================================================
# Verification
# =============================================================================
Write-Host ""
Write-Log "Перевірка налаштувань..." -Level Info

$scriptBlock = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$moduleLog = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Поточний стан:" -ForegroundColor Yellow
Write-Host "  Script Block Logging: $(if($scriptBlock.EnableScriptBlockLogging -eq 1){'Enabled'}else{'Disabled'})"
Write-Host "  Module Logging: $(if($moduleLog.EnableModuleLogging -eq 1){'Enabled'}else{'Disabled'})"
Write-Host "  Transcription: $(if($EnableTranscription){'Enabled'}else{'Disabled'})"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  PowerShell Logging налаштовано успішно!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Тест логування:" -ForegroundColor Cyan
Write-Host '  Write-Host "Test PowerShell Logging"'
Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5"
Write-Host ""
