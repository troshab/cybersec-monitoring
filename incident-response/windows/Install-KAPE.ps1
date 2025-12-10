<#
.SYNOPSIS
    Download and install KAPE for incident response.

.DESCRIPTION
    Automatically downloads KAPE (Kroll Artifact Parser and Extractor) from
    Eric Zimmerman's GitHub and configures it for evidence collection.
    KAPE is the industry standard for Windows forensic artifact collection.

.PARAMETER InstallPath
    Path where to install KAPE (default: C:\Tools\KAPE)

.PARAMETER SkipSync
    Skip running kape.exe --sync after installation

.EXAMPLE
    .\Install-KAPE.ps1

.EXAMPLE
    .\Install-KAPE.ps1 -InstallPath "E:\IR-Tools\KAPE"

.NOTES
    KAPE by Eric Zimmerman
    Documentation: https://ericzimmerman.github.io/KapeDocs/

    For CERT-UA incidents:
    - Email: cert@cert.gov.ua
    - Phone: +380 44 281 88 25
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InstallPath = "C:\Tools\KAPE",
    [switch]$SkipSync
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# =============================================================================
# Configuration
# =============================================================================
# Eric Zimmerman's tools download page
$EZ_TOOLS_URL = "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
$KAPE_DOWNLOAD_URL = "https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip"

# =============================================================================
# Banner
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KAPE Automatic Installation" -ForegroundColor Cyan
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
    try {
        $version = & $kapeExe --version 2>&1 | Select-Object -First 1
        Write-Host "Version: $version" -ForegroundColor Cyan
    } catch {
        Write-Host "Version: Unknown" -ForegroundColor Yellow
    }

    $reinstall = Read-Host "Reinstall/Update KAPE? (y/n)"
    if ($reinstall -ne 'y') {
        Write-Host "Skipping download..." -ForegroundColor Yellow
        $skipDownload = $true
    }
} else {
    $skipDownload = $false
}

# =============================================================================
# Download KAPE
# =============================================================================
if (-not $skipDownload) {
    Write-Host ""
    Write-Host "[*] Downloading KAPE..." -ForegroundColor Cyan

    $tempZip = Join-Path $env:TEMP "kape_download.zip"

    try {
        # Try direct S3 download first (official KAPE distribution)
        Write-Host "[*] Attempting download from official source..." -ForegroundColor Cyan

        # Use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Download KAPE zip
        Invoke-WebRequest -Uri $KAPE_DOWNLOAD_URL -OutFile $tempZip -UseBasicParsing

        if (Test-Path $tempZip) {
            $zipSize = (Get-Item $tempZip).Length / 1MB
            Write-Host "[+] Downloaded: $([math]::Round($zipSize, 2)) MB" -ForegroundColor Green

            # Extract
            Write-Host "[*] Extracting KAPE..." -ForegroundColor Cyan

            # Remove old files if exist
            Get-ChildItem $InstallPath -File | Where-Object { $_.Name -like "*.exe" -or $_.Name -like "*.dll" } | Remove-Item -Force -ErrorAction SilentlyContinue

            # Extract to install path
            Expand-Archive -Path $tempZip -DestinationPath $InstallPath -Force

            # KAPE zip extracts to KAPE subfolder, move files up if needed
            $kapeSubfolder = Join-Path $InstallPath "KAPE"
            if (Test-Path $kapeSubfolder) {
                Get-ChildItem $kapeSubfolder -Recurse | Move-Item -Destination $InstallPath -Force -ErrorAction SilentlyContinue
                Remove-Item $kapeSubfolder -Recurse -Force -ErrorAction SilentlyContinue
            }

            # Cleanup
            Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

            if (Test-Path $kapeExe) {
                Write-Host "[+] KAPE installed successfully!" -ForegroundColor Green
            } else {
                throw "kape.exe not found after extraction"
            }
        }
    }
    catch {
        Write-Host "[!] Direct download failed: $_" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[*] Trying alternative method (Get-ZimmermanTools)..." -ForegroundColor Cyan

        try {
            # Download Get-ZimmermanTools script
            $getZTScript = Join-Path $env:TEMP "Get-ZimmermanTools.ps1"
            Invoke-WebRequest -Uri $EZ_TOOLS_URL -OutFile $getZTScript -UseBasicParsing

            # Run it to download KAPE
            & $getZTScript -Dest $InstallPath -NetVersion 4.8 -ToolList kape

            Remove-Item $getZTScript -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[-] Automatic download failed: $_" -ForegroundColor Red
            Write-Host ""
            Write-Host "Manual download required:" -ForegroundColor Yellow
            Write-Host "  1. Go to: https://www.kroll.com/kape" -ForegroundColor White
            Write-Host "  2. Or: https://ericzimmerman.github.io/#!index.md" -ForegroundColor White
            Write-Host "  3. Download KAPE and extract to: $InstallPath" -ForegroundColor White
            Write-Host ""
        }
    }
}

# =============================================================================
# Sync targets and modules
# =============================================================================
if ((Test-Path $kapeExe) -and (-not $SkipSync)) {
    Write-Host ""
    Write-Host "[*] Syncing KAPE targets and modules..." -ForegroundColor Cyan
    Write-Host "    (This downloads latest detection rules from GitHub)" -ForegroundColor Gray

    try {
        Push-Location $InstallPath
        $syncOutput = & $kapeExe --sync 2>&1
        Pop-Location

        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Sync completed!" -ForegroundColor Green
        } else {
            Write-Host "[!] Sync had warnings (may still be usable)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Sync failed: $_" -ForegroundColor Yellow
        Write-Host "    You can run 'kape.exe --sync' manually later" -ForegroundColor Gray
    }
}

# =============================================================================
# Create collection scripts
# =============================================================================
Write-Host ""
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

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !SANS_Triage --vhdx EVIDENCE

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

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !BasicCollection,!SANS_Triage,RegistryHives,EventLogs,Prefetch,SRUM,Amcache --vhdx EVIDENCE

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

"%KAPE_PATH%kape.exe" --tsource C: --tdest "%OUTPUT_PATH%" --target !SANS_Triage --msource C: --mdest "%OUTPUT_PATH%\Modules" --module !EZParser --vhdx EVIDENCE

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

### Update targets/modules:
``````
kape.exe --sync
``````

## Key Targets

- ``!SANS_Triage`` - SANS forensic triage collection
- ``!BasicCollection`` - Basic artifacts (registry, events, prefetch)
- ``EventLogs`` - All Windows Event Logs
- ``RegistryHives`` - SAM, SYSTEM, SOFTWARE, SECURITY
- ``Prefetch`` - Prefetch files
- ``SRUM`` - System Resource Usage Monitor
- ``Amcache`` - Application compatibility cache

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
# Add to PATH
# =============================================================================
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallPath", "Machine")
    Write-Host "[+] Added KAPE to system PATH" -ForegroundColor Green
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "KAPE directory: $InstallPath" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $kapeExe) {
    try {
        $version = & $kapeExe --version 2>&1 | Select-Object -First 1
        Write-Host "Version: $version" -ForegroundColor Cyan
    } catch {}

    Write-Host ""
    Write-Host "Collection scripts ready:" -ForegroundColor Yellow
    Write-Host "  - Collect-QuickTriage.bat (fast, essential artifacts)" -ForegroundColor White
    Write-Host "  - Collect-Full.bat (comprehensive)" -ForegroundColor White
    Write-Host "  - Collect-WithMemory.bat (with memory dump)" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor Yellow
    Write-Host "  cd $InstallPath" -ForegroundColor White
    Write-Host "  .\Collect-QuickTriage.bat" -ForegroundColor White
} else {
    Write-Host "KAPE download failed. Please download manually:" -ForegroundColor Yellow
    Write-Host "  1. https://www.kroll.com/kape" -ForegroundColor White
    Write-Host "  2. Extract to $InstallPath" -ForegroundColor White
    Write-Host "  3. Run: kape.exe --sync" -ForegroundColor White
}

Write-Host ""
