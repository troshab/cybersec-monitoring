<#
.SYNOPSIS
    Швидкий фікс сервісів Sysmon, Alloy, Osquery
.DESCRIPTION
    Запустити від імені адміністратора після Diagnose-Installation.ps1
.EXAMPLE
    .\Fix-Services.ps1
#>

#Requires -RunAsAdministrator

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Fix Services - Sysmon, Alloy, Osquery" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. FIX SYSMON - Install service if files exist but service missing
# =============================================================================
Write-Host "=== SYSMON ===" -ForegroundColor Yellow

$sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
$sysmonExe = "C:\Program Files\Sysmon\Sysmon64.exe"
$sysmonConfig = "C:\Program Files\Sysmon\sysmonconfig.xml"

if (-not $sysmonSvc -and (Test-Path $sysmonExe)) {
    Write-Host "  [*] Sysmon files exist but service missing. Installing..." -ForegroundColor Cyan

    if (Test-Path $sysmonConfig) {
        $result = & $sysmonExe -accepteula -i $sysmonConfig 2>&1
    } else {
        # Download config
        Write-Host "  [*] Downloading SwiftOnSecurity config..." -ForegroundColor Cyan
        $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
        Invoke-WebRequest -Uri $configUrl -OutFile $sysmonConfig -UseBasicParsing
        $result = & $sysmonExe -accepteula -i $sysmonConfig 2>&1
    }

    Start-Sleep -Seconds 2
    $sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

    if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
        Write-Host "  [+] Sysmon installed and running!" -ForegroundColor Green
    } else {
        Write-Host "  [-] Sysmon installation failed: $result" -ForegroundColor Red
    }
} elseif ($sysmonSvc) {
    if ($sysmonSvc.Status -ne "Running") {
        Write-Host "  [*] Starting Sysmon service..." -ForegroundColor Cyan
        Start-Service -Name $sysmonSvc.Name
        Start-Sleep -Seconds 2
    }
    $sysmonSvc = Get-Service -Name "Sysmon*"
    Write-Host "  [+] Sysmon: $($sysmonSvc.Status)" -ForegroundColor Green
} else {
    Write-Host "  [-] Sysmon not found. Run 03-Install-Sysmon.ps1 first." -ForegroundColor Red
}

Write-Host ""

# =============================================================================
# 2. FIX ALLOY - Just start the service
# =============================================================================
Write-Host "=== ALLOY ===" -ForegroundColor Yellow

$alloySvc = Get-Service -Name "Alloy" -ErrorAction SilentlyContinue

if ($alloySvc) {
    if ($alloySvc.Status -ne "Running") {
        Write-Host "  [*] Starting Alloy service..." -ForegroundColor Cyan
        try {
            Start-Service -Name "Alloy" -ErrorAction Stop
            Start-Sleep -Seconds 3
            $alloySvc = Get-Service -Name "Alloy"
            Write-Host "  [+] Alloy: $($alloySvc.Status)" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Cannot start Alloy: $_" -ForegroundColor Red

            # Try to run manually to see error
            Write-Host "  [*] Trying manual run to see error..." -ForegroundColor Cyan
            $alloyExe = "C:\Program Files\GrafanaLabs\Alloy\alloy-windows-amd64.exe"
            $alloyConfig = "C:\ProgramData\GrafanaLabs\Alloy\config.alloy"
            if ((Test-Path $alloyExe) -and (Test-Path $alloyConfig)) {
                $testResult = & $alloyExe run $alloyConfig --storage.path="C:\ProgramData\GrafanaLabs\Alloy\data" 2>&1
                Write-Host "  Output: $testResult" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [+] Alloy: Already Running" -ForegroundColor Green
    }
} else {
    Write-Host "  [-] Alloy service not found. Run 04-Install-Alloy.ps1 first." -ForegroundColor Red
}

Write-Host ""

# =============================================================================
# 3. FIX OSQUERY - Re-register with correct path
# =============================================================================
Write-Host "=== OSQUERY ===" -ForegroundColor Yellow

$osquerySvc = Get-Service -Name "osqueryd" -ErrorAction SilentlyContinue

# Find osqueryd.exe (it's in a subfolder!)
$osqueryExe = $null
$searchPaths = @(
    "C:\Program Files\osquery\osqueryd\osqueryd.exe",
    "C:\Program Files\osquery\osqueryd.exe",
    "C:\ProgramData\osquery\osqueryd.exe"
)
foreach ($p in $searchPaths) {
    if (Test-Path $p) {
        $osqueryExe = $p
        break
    }
}

$osqueryDir = Split-Path -Parent $osqueryExe
$osqueryBaseDir = "C:\Program Files\osquery"
$flagsFile = "$osqueryBaseDir\osquery.flags"

if ($osqueryExe) {
    Write-Host "  [*] Found osqueryd: $osqueryExe" -ForegroundColor Cyan

    # Check if flags file exists
    if (-not (Test-Path $flagsFile)) {
        Write-Host "  [-] Flags file missing: $flagsFile" -ForegroundColor Red
        Write-Host "  [*] Creating basic flags file..." -ForegroundColor Cyan

        # Create basic flags for FleetDM
        $flags = @"
--tls_hostname=10.0.1.2:8080
--enroll_secret_path=C:\Program Files\osquery\enroll_secret
--host_identifier=hostname
--enroll_tls_endpoint=/api/osquery/enroll
--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_refresh=10
--disable_distributed=false
--distributed_plugin=tls
--distributed_interval=10
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
--insecure
"@
        $flags | Out-File -FilePath $flagsFile -Encoding ASCII
        Write-Host "  [+] Created flags file with --insecure mode" -ForegroundColor Green

        # Check enroll secret
        $secretFile = "$osqueryBaseDir\enroll_secret"
        if (-not (Test-Path $secretFile)) {
            Write-Host "  [!] Enter FleetDM enroll secret:" -ForegroundColor Yellow
            $secret = Read-Host
            if ($secret) {
                $secret | Out-File -FilePath $secretFile -Encoding ASCII -NoNewline
                Write-Host "  [+] Saved enroll secret" -ForegroundColor Green
            }
        }
    }

    # Stop existing service
    if ($osquerySvc) {
        Write-Host "  [*] Stopping existing service..." -ForegroundColor Cyan
        Stop-Service -Name "osqueryd" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Uninstall and reinstall service
    Write-Host "  [*] Re-registering service..." -ForegroundColor Cyan
    & $osqueryExe --uninstall 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    $installResult = & $osqueryExe --install --flagfile=$flagsFile 2>&1
    Start-Sleep -Seconds 2

    # Start service
    Write-Host "  [*] Starting osqueryd service..." -ForegroundColor Cyan
    try {
        Start-Service -Name "osqueryd" -ErrorAction Stop
        Start-Sleep -Seconds 3
        $osquerySvc = Get-Service -Name "osqueryd"
        Write-Host "  [+] Osquery: $($osquerySvc.Status)" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Cannot start osqueryd: $_" -ForegroundColor Red

        # Show log
        $logFile = "$osqueryBaseDir\osqueryd.results.log"
        if (Test-Path $logFile) {
            Write-Host "  Recent log:" -ForegroundColor Yellow
            Get-Content $logFile -Tail 5 | ForEach-Object { Write-Host "    $_" }
        }
    }
} else {
    Write-Host "  [-] osqueryd.exe not found. Run 06-Install-OsqueryAgent.ps1 first." -ForegroundColor Red
}

Write-Host ""

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$services = @(
    @{Name="Sysmon64"; Display="Sysmon"},
    @{Name="Sysmon"; Display="Sysmon"},
    @{Name="Alloy"; Display="Alloy"},
    @{Name="osqueryd"; Display="Osquery"}
)

foreach ($s in $services) {
    $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
    if ($svc) {
        $color = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "  $($s.Display): $($svc.Status)" -ForegroundColor $color
    }
}

Write-Host ""
