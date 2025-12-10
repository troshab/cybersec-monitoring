<#
.SYNOPSIS
    Download and setup KAPE for incident response.

.DESCRIPTION
    Downloads KAPE (Kroll Artifact Parser and Extractor) and configures it
    for evidence collection. KAPE is the industry standard for Windows
    forensic artifact collection.

    KAPE must be downloaded manually from Kroll's website due to licensing.
    This script prepares the directory structure and provides instructions.

.PARAMETER InstallPath
    Path where to install KAPE (default: C:\Tools\KAPE)

.EXAMPLE
    .\Install-KAPE.ps1

.EXAMPLE
    .\Install-KAPE.ps1 -InstallPath "E:\IR-Tools\KAPE"

.NOTES
    KAPE Download: https://www.kroll.com/kape
    Documentation: https://ericzimmerman.github.io/KapeDocs/

    For CERT-UA incidents:
    - Email: cert@cert.gov.ua
    - Phone: +380 44 281 88 25
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InstallPath = "C:\Tools\KAPE"
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Banner
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KAPE Setup for Incident Response" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Create directory structure
# =============================================================================
Write-Host "[*] Creating directory structure..." -ForegroundColor Cyan

$directories = @(
    $InstallPath,
    "$InstallPath\Targets",
    "$InstallPath\Modules",
    "$InstallPath\Output"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Host "[+] Created: $dir" -ForegroundColor Green
    }
}

# =============================================================================
# Check if KAPE already exists
# =============================================================================
$kapeExe = Join-Path $InstallPath "kape.exe"

if (Test-Path $kapeExe) {
    Write-Host "[+] KAPE already installed at $InstallPath" -ForegroundColor Green
    Write-Host ""

    # Show version
    $version = & $kapeExe --version 2>&1 | Select-Object -First 1
    Write-Host "Version: $version" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "[!] KAPE not found. Manual download required." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "KAPE requires manual download due to licensing:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Go to: https://www.kroll.com/kape" -ForegroundColor Cyan
    Write-Host "  2. Fill out the form to download KAPE" -ForegroundColor Cyan
    Write-Host "  3. Extract to: $InstallPath" -ForegroundColor Cyan
    Write-Host ""
}

# =============================================================================
# Create collection scripts
# =============================================================================
Write-Host "[*] Creating collection scripts..." -ForegroundColor Cyan

# Quick triage script
$quickTriageScript = @'
@echo off
REM KAPE Quick Triage Collection
REM For incident response - collects essential artifacts

set KAPE_PATH=%~dp0
set OUTPUT_PATH=%~dp0Output\%COMPUTERNAME%_%DATE:~-4,4%%DATE:~-7,2%%DATE:~-10,2%_%TIME:~0,2%%TIME:~3,2%
set OUTPUT_PATH=%OUTPUT_PATH: =0%

echo ============================================================
echo   KAPE Quick Triage Collection
echo ============================================================
echo.
echo Target: %COMPUTERNAME%
echo Output: %OUTPUT_PATH%
echo.

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !SANS_Triage --vhdx EVIDENCE --gui

echo.
echo Collection complete!
echo Output: %OUTPUT_PATH%
echo.
pause
'@

$quickTriageScript | Out-File -FilePath "$InstallPath\Collect-QuickTriage.bat" -Encoding ASCII
Write-Host "[+] Created: Collect-QuickTriage.bat" -ForegroundColor Green

# Full collection script
$fullCollectionScript = @'
@echo off
REM KAPE Full Evidence Collection
REM Comprehensive artifact collection for detailed investigation

set KAPE_PATH=%~dp0
set OUTPUT_PATH=%~dp0Output\%COMPUTERNAME%_%DATE:~-4,4%%DATE:~-7,2%%DATE:~-10,2%_%TIME:~0,2%%TIME:~3,2%
set OUTPUT_PATH=%OUTPUT_PATH: =0%

echo ============================================================
echo   KAPE Full Evidence Collection
echo ============================================================
echo.
echo Target: %COMPUTERNAME%
echo Output: %OUTPUT_PATH%
echo.
echo This will collect comprehensive forensic artifacts.
echo Estimated time: 30-60 minutes depending on system
echo.
pause

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !BasicCollection,!SANS_Triage,RegistryHives,EventLogs,Prefetch,SRUM,Amcache --vhdx EVIDENCE --gui

echo.
echo Collection complete!
echo Output: %OUTPUT_PATH%
echo.
pause
'@

$fullCollectionScript | Out-File -FilePath "$InstallPath\Collect-Full.bat" -Encoding ASCII
Write-Host "[+] Created: Collect-Full.bat" -ForegroundColor Green

# Memory + artifacts script
$memoryScript = @'
@echo off
REM KAPE with Memory Collection
REM Requires winpmem driver

set KAPE_PATH=%~dp0
set OUTPUT_PATH=%~dp0Output\%COMPUTERNAME%_%DATE:~-4,4%%DATE:~-7,2%%DATE:~-10,2%_%TIME:~0,2%%TIME:~3,2%
set OUTPUT_PATH=%OUTPUT_PATH: =0%

echo ============================================================
echo   KAPE + Memory Collection
echo ============================================================
echo.
echo WARNING: Memory collection requires significant disk space
echo          and may take 15-30 minutes.
echo.
pause

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !SANS_Triage --msource C: --mdest "%OUTPUT_PATH%\Modules" --module !EZParser --vhdx EVIDENCE --gui

echo.
echo Collection complete!
echo Output: %OUTPUT_PATH%
echo.
pause
'@

$memoryScript | Out-File -FilePath "$InstallPath\Collect-WithMemory.bat" -Encoding ASCII
Write-Host "[+] Created: Collect-WithMemory.bat" -ForegroundColor Green

# =============================================================================
# Create README
# =============================================================================
$readmeContent = @"
# KAPE - Kroll Artifact Parser and Extractor

## Installation

1. Download KAPE from: https://www.kroll.com/kape
2. Extract the contents to this directory
3. Run `kape.exe --sync` to update targets and modules

## Collection Scripts

- **Collect-QuickTriage.bat** - Fast collection of essential artifacts (~5-10 min)
- **Collect-Full.bat** - Comprehensive collection (~30-60 min)
- **Collect-WithMemory.bat** - Artifacts + memory dump

## Command Line Usage

### Quick triage:
``````
kape.exe --tsource C: --tdest E:\Evidence --target !SANS_Triage --vhdx EVIDENCE
``````

### Full collection:
``````
kape.exe --tsource C: --tdest E:\Evidence --target !BasicCollection,EventLogs,RegistryHives --vhdx EVIDENCE
``````

### With module processing:
``````
kape.exe --tsource C: --tdest E:\Evidence --target !SANS_Triage --mdest E:\Evidence\Modules --module !EZParser
``````

## Key Targets

- `!SANS_Triage` - SANS forensic triage collection
- `!BasicCollection` - Basic artifacts (registry, events, prefetch)
- `EventLogs` - All Windows Event Logs
- `RegistryHives` - SAM, SYSTEM, SOFTWARE, SECURITY
- `Prefetch` - Prefetch files
- `SRUM` - System Resource Usage Monitor
- `Amcache` - Application compatibility cache

## CERT-UA Contact

After collecting evidence:
- Email: cert@cert.gov.ua
- Phone: +380 44 281 88 25
- Web: https://cert.gov.ua

## Resources

- KAPE Documentation: https://ericzimmerman.github.io/KapeDocs/
- Target/Module Reference: https://github.com/EricZimmerman/KapeFiles
"@

$readmeContent | Out-File -FilePath "$InstallPath\README.md" -Encoding UTF8
Write-Host "[+] Created: README.md" -ForegroundColor Green

# =============================================================================
# Add to PATH (optional)
# =============================================================================
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    Write-Host ""
    $addToPath = Read-Host "Add KAPE to system PATH? (y/n)"
    if ($addToPath -eq 'y') {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallPath", "Machine")
        Write-Host "[+] Added to PATH" -ForegroundColor Green
    }
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Setup Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "KAPE directory: $InstallPath" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $kapeExe)) {
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Download KAPE from https://www.kroll.com/kape" -ForegroundColor White
    Write-Host "  2. Extract to $InstallPath" -ForegroundColor White
    Write-Host "  3. Run: kape.exe --sync (to update targets)" -ForegroundColor White
} else {
    Write-Host "Ready to use! Collection scripts:" -ForegroundColor Yellow
    Write-Host "  - Collect-QuickTriage.bat (fast, essential artifacts)" -ForegroundColor White
    Write-Host "  - Collect-Full.bat (comprehensive)" -ForegroundColor White
    Write-Host "  - Collect-WithMemory.bat (with memory dump)" -ForegroundColor White
}

Write-Host ""
