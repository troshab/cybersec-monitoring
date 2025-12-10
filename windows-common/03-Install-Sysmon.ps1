<#
.SYNOPSIS
    Install and configure Sysmon.

.DESCRIPTION
    Downloads and installs Sysmon with SwiftOnSecurity configuration
    for detailed monitoring of processes, network connections, files, etc.

    Sysmon Events:
    - Event 1: Process creation
    - Event 3: Network connection
    - Event 7: Image loaded
    - Event 11: File created
    - Event 12/13: Registry changes
    - Event 22: DNS query

.PARAMETER ConfigUrl
    URL to configuration file (default SwiftOnSecurity)

.PARAMETER ConfigPath
    Local path to configuration (if already exists)

.EXAMPLE
    .\03-Install-Sysmon.ps1
    Installs Sysmon with SwiftOnSecurity configuration

.EXAMPLE
    .\03-Install-Sysmon.ps1 -ConfigPath "C:\Config\sysmon.xml"
    Uses custom configuration

.NOTES
    Requires administrator rights
    Sysmon runs as a driver - requires reboot for some changes
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    $colors = @{ 'Info' = 'Cyan'; 'Success' = 'Green'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $prefix = @{ 'Info' = '[*]'; 'Success' = '[+]'; 'Warning' = '[!]'; 'Error' = '[-]' }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Sysmon Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$sysmonDir = "C:\Program Files\Sysmon"
$tempDir = "$env:TEMP\sysmon_install"

# =============================================================================
# Checking if already installed
# =============================================================================
$existingSysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

# Find Sysmon executable (could be in different locations)
$sysmonExe = $null
$possiblePaths = @(
    "$sysmonDir\Sysmon64.exe",
    "$sysmonDir\Sysmon.exe",
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\Sysmon.exe"
)
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $sysmonExe = $path
        break
    }
}

# Case 1: Service exists - just update config
if ($existingSysmon) {
    Write-Log "Sysmon already installed: $($existingSysmon.Name)" -Level Warning
    Write-Log "Updating configuration..." -Level Info

    if (-not $sysmonExe) {
        # Try to find via service image path
        $svc = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Sysmon%'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.PathName) {
            $sysmonExe = $svc.PathName.Trim('"').Split(' ')[0]
        }
    }

    if ($sysmonExe -and (Test-Path $sysmonExe)) {
        if ($ConfigPath -and (Test-Path $ConfigPath)) {
            & $sysmonExe -c $ConfigPath 2>&1 | Out-Null
        } else {
            # Downloading new configuration
            $tempConfig = "$tempDir\sysmonconfig.xml"
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            Invoke-WebRequest -Uri $ConfigUrl -OutFile $tempConfig -UseBasicParsing
            & $sysmonExe -c $tempConfig 2>&1 | Out-Null
        }
        Write-Log "Configuration updated" -Level Success
    } else {
        Write-Log "Cannot find Sysmon executable, skipping config update" -Level Warning
    }
    exit 0
}

# Case 2: Files exist but service missing - install service
if ($sysmonExe -and -not $existingSysmon) {
    Write-Log "Sysmon files found but service missing. Installing service..." -Level Warning

    # Get or download config
    $configFile = "$sysmonDir\sysmonconfig.xml"
    if (-not (Test-Path $configFile)) {
        if ($ConfigPath -and (Test-Path $ConfigPath)) {
            Copy-Item $ConfigPath -Destination $configFile
        } else {
            Write-Log "Downloading SwiftOnSecurity configuration..." -Level Info
            Invoke-WebRequest -Uri $ConfigUrl -OutFile $configFile -UseBasicParsing
        }
    }

    # Install with -accepteula
    Write-Log "Installing Sysmon service..." -Level Info
    $result = & $sysmonExe -accepteula -i $configFile 2>&1

    Start-Sleep -Seconds 3
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

    if ($sysmonService -and $sysmonService.Status -eq "Running") {
        Write-Log "Sysmon service installed and running!" -Level Success
    } elseif ($sysmonService) {
        Write-Log "Sysmon service installed: $($sysmonService.Status)" -Level Success
        Start-Service -Name $sysmonService.Name -ErrorAction SilentlyContinue
    } else {
        Write-Log "Failed to install Sysmon service: $result" -Level Error
    }
    exit 0
}

# =============================================================================
# Завантаження Sysmon
# =============================================================================
Write-Log "Downloading Sysmon..." -Level Info

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$tempDir\Sysmon.zip"

try {
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
} catch {
    Write-Log "Download error: $_" -Level Error
    exit 1
}

# Extracting
Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force

# =============================================================================
# Завантаження конфігурації
# =============================================================================
Write-Log "Downloading configuration..." -Level Info

$configFile = "$tempDir\sysmonconfig.xml"

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    Copy-Item $ConfigPath -Destination $configFile
    Write-Log "Using local configuration: $ConfigPath" -Level Info
} else {
    try {
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $configFile -UseBasicParsing
        Write-Log "Downloaded SwiftOnSecurity configuration" -Level Success
    } catch {
        Write-Log "Configuration download error: $_" -Level Error
        exit 1
    }
}

# =============================================================================
# Встановлення
# =============================================================================
Write-Log "Installing Sysmon..." -Level Info

# Creating directory
New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null

# Copying files
Copy-Item "$tempDir\Sysmon64.exe" -Destination $sysmonDir
Copy-Item "$tempDir\Sysmon.exe" -Destination $sysmonDir
Copy-Item $configFile -Destination "$sysmonDir\sysmonconfig.xml"

# Installing with configuration
$sysmonExe = "$sysmonDir\Sysmon64.exe"

$installArgs = @(
    "-accepteula",
    "-i",
    "$sysmonDir\sysmonconfig.xml"
)

$process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Log "Installation error (code: $($process.ExitCode))" -Level Error
    exit 1
}

# =============================================================================
# Verification
# =============================================================================
Start-Sleep -Seconds 3

$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Log "Sysmon installed and running!" -Level Success
} else {
    Write-Log "Sysmon installed but service not started" -Level Warning
    Start-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}

# Тест генерації подій
Write-Log "Verification генерації подій..." -Level Info

try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
    Write-Log "Received $($events.Count) Sysmon events" -Level Success
} catch {
    Write-Log "No events yet (this is normal for newly installed Sysmon)" -Level Warning
}

# =============================================================================
# Cleanup
# =============================================================================
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Sysmon installed successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Sysmon Events:" -ForegroundColor Cyan
Write-Host "  Event 1  - Process creation (with command line)"
Write-Host "  Event 3  - Network connection"
Write-Host "  Event 7  - Image loaded (DLL)"
Write-Host "  Event 11 - File created"
Write-Host "  Event 12 - Registry object created/deleted"
Write-Host "  Event 13 - Registry value set"
Write-Host "  Event 22 - DNS query"
Write-Host ""
Write-Host "Verification:" -ForegroundColor Cyan
Write-Host '  Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10'
Write-Host ""
