<#
.SYNOPSIS
    Enable full PowerShell logging.

.DESCRIPTION
    Configures Script Block Logging, Module Logging and optionally Transcription
    for detailed tracking of all PowerShell commands.

    Critical for detecting:
    - Encoded PowerShell commands
    - Download cradles (IEX, Invoke-WebRequest)
    - Malware and lateral movement

.PARAMETER EnableTranscription
    Enable recording of all PowerShell sessions to files (generates a lot of data)

.PARAMETER TranscriptPath
    Path to save transcript files

.EXAMPLE
    .\02-Enable-PowerShellLogging.ps1
    Enables Script Block and Module logging

.EXAMPLE
    .\02-Enable-PowerShellLogging.ps1 -EnableTranscription -TranscriptPath "C:\PSLogs"
    Also enables Transcription

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
Write-Log "Configuring Script Block Logging..." -Level Info

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

Write-Log "Script Block Logging enabled" -Level Success

# =============================================================================
# Module Logging (Event ID 4103)
# =============================================================================
Write-Log "Configuring Module Logging..." -Level Info

# 64-bit
$modPath64 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modPath64)) {
    New-Item -Path $modPath64 -Force | Out-Null
}
Set-ItemProperty -Path $modPath64 -Name "EnableModuleLogging" -Value 1 -Type DWord

# Module Names (log all modules)
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

Write-Log "Module Logging enabled" -Level Success

# =============================================================================
# Transcription (optional)
# =============================================================================
if ($EnableTranscription) {
    Write-Log "Configuring Transcription..." -Level Info

    # Creating directory for logs
    if (-not (Test-Path $TranscriptPath)) {
        New-Item -ItemType Directory -Path $TranscriptPath -Force | Out-Null
    }

    # Access permissions (only admins can read)
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

    Write-Log "Transcription enabled. Logs: $TranscriptPath" -Level Success
} else {
    Write-Log "Transcription skipped (use -EnableTranscription to enable)" -Level Warning
}

# =============================================================================
# Event Log Size
# =============================================================================
Write-Log "Increasing PowerShell Event Log size..." -Level Info

wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
wevtutil sl "Windows PowerShell" /ms:134217728

Write-Log "Log size: 256MB" -Level Success

# =============================================================================
# Verification
# =============================================================================
Write-Host ""
Write-Log "Verifying settings..." -Level Info

$scriptBlock = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$moduleLog = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Current status:" -ForegroundColor Yellow
Write-Host "  Script Block Logging: $(if($scriptBlock.EnableScriptBlockLogging -eq 1){'Enabled'}else{'Disabled'})"
Write-Host "  Module Logging: $(if($moduleLog.EnableModuleLogging -eq 1){'Enabled'}else{'Disabled'})"
Write-Host "  Transcription: $(if($EnableTranscription){'Enabled'}else{'Disabled'})"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  PowerShell Logging configured successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Logging test:" -ForegroundColor Cyan
Write-Host '  Write-Host "Test PowerShell Logging"'
Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5"
Write-Host ""
