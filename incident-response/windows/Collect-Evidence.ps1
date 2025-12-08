<#
.SYNOPSIS
    Collect forensic evidence for CERT-UA submission.

.DESCRIPTION
    KAPE-style evidence collection script for Windows systems.
    Collects critical artifacts for incident investigation.

    Based on SANS FOR500 and CERT-UA recommendations.

.PARAMETER OutputPath
    Path to save collected evidence (default: Desktop\Evidence_<hostname>_<date>)

.PARAMETER SkipVolatile
    Skip volatile data collection (processes, network)

.PARAMETER Quick
    Quick collection - only most critical artifacts

.EXAMPLE
    .\Collect-Evidence.ps1

.EXAMPLE
    .\Collect-Evidence.ps1 -OutputPath "E:\Evidence"

.EXAMPLE
    .\Collect-Evidence.ps1 -Quick

.NOTES
    Run as Administrator!
    For CERT-UA incident response.

    Contact CERT-UA:
    - Email: cert@cert.gov.ua
    - Phone: +380 44 281 88 25
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [switch]$SkipVolatile,
    [switch]$Quick
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# =============================================================================
# Configuration
# =============================================================================
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CollectorVersion = "1.0"

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Evidence_${Hostname}_${Timestamp}"
}

# =============================================================================
# Functions
# =============================================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
    Add-Content -Path "$OutputPath\collection.log" -Value "[$ts] [$Level] $Message" -ErrorAction SilentlyContinue
}

function New-EvidenceFolder {
    param([string]$Name)
    $path = Join-Path $OutputPath $Name
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    return $path
}

function Copy-SafeItem {
    param([string]$Source, [string]$Destination)
    try {
        if (Test-Path $Source) {
            Copy-Item -Path $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
            Write-Log "Copied: $Source" -Level SUCCESS
        } else {
            Write-Log "Not found: $Source" -Level WARNING
        }
    } catch {
        Write-Log "Failed to copy $Source : $_" -Level ERROR
    }
}

function Export-RegistryHive {
    param([string]$HivePath, [string]$OutputFile)
    try {
        $regPath = "HKLM:\$HivePath"
        if (Test-Path $regPath) {
            reg save "HKLM\$HivePath" $OutputFile /y 2>&1 | Out-Null
            Write-Log "Exported registry: $HivePath" -Level SUCCESS
        }
    } catch {
        Write-Log "Failed to export registry $HivePath : $_" -Level ERROR
    }
}

# =============================================================================
# Banner
# =============================================================================
Clear-Host
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Windows Evidence Collection for CERT-UA" -ForegroundColor Cyan
Write-Host "  Version: $CollectorVersion" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host @"
 ██████╗███████╗██████╗ ████████╗    ██╗   ██╗ █████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝    ██║   ██║██╔══██╗
██║     █████╗  ██████╔╝   ██║       ██║   ██║███████║
██║     ██╔══╝  ██╔══██╗   ██║       ██║   ██║██╔══██║
╚██████╗███████╗██║  ██║   ██║       ╚██████╔╝██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚═╝  ╚═╝
"@ -ForegroundColor Yellow

Write-Host ""
Write-Host "Target: $Hostname" -ForegroundColor White
Write-Host "Output: $OutputPath" -ForegroundColor White
Write-Host "Mode: $(if($Quick){'Quick'}else{'Full'})" -ForegroundColor White
Write-Host ""

# Confirm
$confirm = Read-Host "Start evidence collection? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Cancelled by user" -ForegroundColor Yellow
    exit 0
}

# =============================================================================
# Initialize
# =============================================================================
$StartTime = Get-Date
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

Write-Log "Evidence collection started"
Write-Log "Hostname: $Hostname"
Write-Log "User: $env:USERNAME"
Write-Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"

# =============================================================================
# 1. VOLATILE DATA (collect first!)
# =============================================================================
if (-not $SkipVolatile) {
    Write-Host ""
    Write-Host "[1/8] Collecting VOLATILE DATA..." -ForegroundColor Magenta
    $volatilePath = New-EvidenceFolder "01_Volatile"

    # Running processes
    Write-Log "Collecting running processes..."
    Get-Process | Select-Object Id, ProcessName, Path, Company, StartTime, CPU, WorkingSet64 |
        Export-Csv "$volatilePath\processes.csv" -NoTypeInformation

    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId, CreationDate |
        Export-Csv "$volatilePath\processes_detailed.csv" -NoTypeInformation

    # Network connections
    Write-Log "Collecting network connections..."
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
        Export-Csv "$volatilePath\netstat_tcp.csv" -NoTypeInformation

    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime |
        Export-Csv "$volatilePath\netstat_udp.csv" -NoTypeInformation

    # DNS cache
    Write-Log "Collecting DNS cache..."
    Get-DnsClientCache | Export-Csv "$volatilePath\dns_cache.csv" -NoTypeInformation

    # ARP cache
    Write-Log "Collecting ARP cache..."
    Get-NetNeighbor | Export-Csv "$volatilePath\arp_cache.csv" -NoTypeInformation

    # Logged on users
    Write-Log "Collecting logged on users..."
    query user 2>$null | Out-File "$volatilePath\logged_users.txt"

    # Open handles (requires Sysinternals handle.exe)
    if (Test-Path "C:\Tools\handle.exe") {
        Write-Log "Collecting open handles..."
        & "C:\Tools\handle.exe" -a 2>$null | Out-File "$volatilePath\handles.txt"
    }
}

# =============================================================================
# 2. EVENT LOGS
# =============================================================================
Write-Host ""
Write-Host "[2/8] Collecting EVENT LOGS..." -ForegroundColor Magenta
$logsPath = New-EvidenceFolder "02_EventLogs"

$eventLogs = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-WMI-Activity/Operational"
)

foreach ($logName in $eventLogs) {
    try {
        $safeName = $logName -replace '[/\\]', '_'
        $logPath = "$logsPath\$safeName.evtx"

        # Export using wevtutil
        wevtutil epl $logName $logPath /ow:true 2>$null

        if (Test-Path $logPath) {
            Write-Log "Exported: $logName" -Level SUCCESS
        } else {
            Write-Log "Failed or empty: $logName" -Level WARNING
        }
    } catch {
        Write-Log "Error exporting $logName : $_" -Level ERROR
    }
}

# =============================================================================
# 3. REGISTRY HIVES
# =============================================================================
Write-Host ""
Write-Host "[3/8] Collecting REGISTRY HIVES..." -ForegroundColor Magenta
$regPath = New-EvidenceFolder "03_Registry"

# System hives
Export-RegistryHive "SAM" "$regPath\SAM"
Export-RegistryHive "SYSTEM" "$regPath\SYSTEM"
Export-RegistryHive "SOFTWARE" "$regPath\SOFTWARE"
Export-RegistryHive "SECURITY" "$regPath\SECURITY"

# User hives (NTUSER.DAT)
$users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($user in $users) {
    $ntuser = Join-Path $user.FullName "NTUSER.DAT"
    if (Test-Path $ntuser) {
        try {
            Copy-Item $ntuser "$regPath\NTUSER_$($user.Name).DAT" -Force -ErrorAction Stop
            Write-Log "Copied NTUSER.DAT for $($user.Name)" -Level SUCCESS
        } catch {
            Write-Log "Could not copy NTUSER.DAT for $($user.Name) (in use)" -Level WARNING
        }
    }
}

# =============================================================================
# 4. PREFETCH
# =============================================================================
if (-not $Quick) {
    Write-Host ""
    Write-Host "[4/8] Collecting PREFETCH..." -ForegroundColor Magenta
    $prefetchPath = New-EvidenceFolder "04_Prefetch"

    Copy-SafeItem "C:\Windows\Prefetch\*" $prefetchPath
}

# =============================================================================
# 5. SCHEDULED TASKS
# =============================================================================
Write-Host ""
Write-Host "[5/8] Collecting SCHEDULED TASKS..." -ForegroundColor Magenta
$tasksPath = New-EvidenceFolder "05_ScheduledTasks"

# Export all tasks
Get-ScheduledTask | ForEach-Object {
    $taskInfo = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        State = $_.State
        Author = $_.Author
        Actions = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
        Triggers = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "; "
        LastRunTime = $taskInfo.LastRunTime
        NextRunTime = $taskInfo.NextRunTime
        LastTaskResult = $taskInfo.LastTaskResult
    }
} | Export-Csv "$tasksPath\scheduled_tasks.csv" -NoTypeInformation

# Copy task XML files
Copy-SafeItem "C:\Windows\System32\Tasks\*" "$tasksPath\TaskFiles"

# =============================================================================
# 6. SERVICES & STARTUP
# =============================================================================
Write-Host ""
Write-Host "[6/8] Collecting SERVICES & STARTUP..." -ForegroundColor Magenta
$servicesPath = New-EvidenceFolder "06_Services"

# Services
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Export-Csv "$servicesPath\services.csv" -NoTypeInformation

# Startup items
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User |
    Export-Csv "$servicesPath\startup_items.csv" -NoTypeInformation

# Autoruns (if Sysinternals available)
if (Test-Path "C:\Tools\autorunsc.exe") {
    Write-Log "Running Autoruns..."
    & "C:\Tools\autorunsc.exe" -a * -c -h -s -v -vt 2>$null | Out-File "$servicesPath\autoruns.csv"
}

# =============================================================================
# 7. USER ARTIFACTS
# =============================================================================
if (-not $Quick) {
    Write-Host ""
    Write-Host "[7/8] Collecting USER ARTIFACTS..." -ForegroundColor Magenta
    $userPath = New-EvidenceFolder "07_UserArtifacts"

    foreach ($user in $users) {
        $userFolder = New-EvidenceFolder "07_UserArtifacts\$($user.Name)"

        # Recent files (LNK)
        Copy-SafeItem (Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent\*") "$userFolder\Recent"

        # Jump Lists
        Copy-SafeItem (Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*") "$userFolder\JumpLists_Auto"
        Copy-SafeItem (Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*") "$userFolder\JumpLists_Custom"

        # PowerShell history
        Copy-SafeItem (Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") $userFolder

        # Browser history (Chrome)
        Copy-SafeItem (Join-Path $user.FullName "AppData\Local\Google\Chrome\User Data\Default\History") "$userFolder\Chrome_History"

        # Browser history (Edge)
        Copy-SafeItem (Join-Path $user.FullName "AppData\Local\Microsoft\Edge\User Data\Default\History") "$userFolder\Edge_History"

        # Browser history (Firefox)
        $firefoxProfile = Get-ChildItem (Join-Path $user.FullName "AppData\Roaming\Mozilla\Firefox\Profiles") -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($firefoxProfile) {
            Copy-SafeItem (Join-Path $firefoxProfile.FullName "places.sqlite") "$userFolder\Firefox_History"
        }
    }
}

# =============================================================================
# 8. SYSTEM INFO
# =============================================================================
Write-Host ""
Write-Host "[8/8] Collecting SYSTEM INFO..." -ForegroundColor Magenta
$infoPath = New-EvidenceFolder "08_SystemInfo"

# System information
systeminfo | Out-File "$infoPath\systeminfo.txt"

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Export-Csv "$infoPath\installed_software.csv" -NoTypeInformation

# Network configuration
ipconfig /all | Out-File "$infoPath\ipconfig.txt"
route print | Out-File "$infoPath\routes.txt"
netsh advfirewall show allprofiles | Out-File "$infoPath\firewall_status.txt"

# Local users and groups
Get-LocalUser | Export-Csv "$infoPath\local_users.csv" -NoTypeInformation
Get-LocalGroup | ForEach-Object {
    $group = $_
    Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Group = $group.Name
            Member = $_.Name
            ObjectClass = $_.ObjectClass
            PrincipalSource = $_.PrincipalSource
        }
    }
} | Export-Csv "$infoPath\local_groups.csv" -NoTypeInformation

# Hotfixes
Get-HotFix | Export-Csv "$infoPath\hotfixes.csv" -NoTypeInformation

# Shares
Get-SmbShare | Export-Csv "$infoPath\shares.csv" -NoTypeInformation

# =============================================================================
# Finalize
# =============================================================================
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Log "Collection completed in $($Duration.TotalMinutes.ToString('0.0')) minutes"

# Calculate hash
Write-Host ""
Write-Host "Creating archive..." -ForegroundColor Cyan

$archiveName = "Evidence_${Hostname}_${Timestamp}.zip"
$archivePath = Join-Path (Split-Path $OutputPath -Parent) $archiveName

Compress-Archive -Path $OutputPath -DestinationPath $archivePath -Force

# Calculate SHA256
$hash = (Get-FileHash $archivePath -Algorithm SHA256).Hash
Write-Log "Archive created: $archivePath"
Write-Log "SHA256: $hash"

# Save hash to file
@"
Evidence Collection Report
==========================
Hostname: $Hostname
Collected by: $env:USERNAME
Start time: $StartTime
End time: $EndTime
Duration: $($Duration.TotalMinutes.ToString('0.0')) minutes

Archive: $archiveName
SHA256: $hash

CERT-UA Contact:
- Email: cert@cert.gov.ua
- Phone: +380 44 281 88 25
- Web: https://cert.gov.ua
"@ | Out-File "$OutputPath\COLLECTION_REPORT.txt"

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Evidence folder: $OutputPath" -ForegroundColor Cyan
Write-Host "Archive: $archivePath" -ForegroundColor Cyan
Write-Host ""
Write-Host "SHA256: $hash" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "1. Copy archive to external drive"
Write-Host "2. Encrypt with GPG: gpg -c $archiveName"
Write-Host "3. Contact CERT-UA: cert@cert.gov.ua"
Write-Host "4. Provide password via phone: +380 44 281 88 25"
Write-Host ""
