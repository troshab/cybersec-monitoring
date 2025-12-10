<#
.SYNOPSIS
    Діагностика встановлення агентів моніторингу.
.DESCRIPTION
    Перевіряє Sysmon, Alloy, Osquery - де встановлені, чому не працюють.
.EXAMPLE
    .\Diagnose-Installation.ps1
#>

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Diagnostics - Monitoring Agents" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. SYSMON
# =============================================================================
Write-Host "=== SYSMON ===" -ForegroundColor Yellow

$sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($sysmonSvc) {
    Write-Host "  Service: $($sysmonSvc.Name) - $($sysmonSvc.Status)" -ForegroundColor Green

    $svcWmi = Get-WmiObject Win32_Service -Filter "Name LIKE 'Sysmon%'" -ErrorAction SilentlyContinue
    if ($svcWmi) {
        Write-Host "  Path: $($svcWmi.PathName)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  Service: NOT FOUND" -ForegroundColor Red
}

# Check common locations
$sysmonPaths = @(
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\Sysmon.exe",
    "C:\Program Files\Sysmon\Sysmon64.exe",
    "C:\Program Files\Sysmon\Sysmon.exe"
)
Write-Host "  Checking paths:" -ForegroundColor Gray
foreach ($p in $sysmonPaths) {
    $exists = Test-Path $p
    $color = if ($exists) { "Green" } else { "DarkGray" }
    Write-Host "    $p : $exists" -ForegroundColor $color
}

Write-Host ""

# =============================================================================
# 2. GRAFANA ALLOY
# =============================================================================
Write-Host "=== GRAFANA ALLOY ===" -ForegroundColor Yellow

$alloySvc = Get-Service -Name "Alloy" -ErrorAction SilentlyContinue
if ($alloySvc) {
    Write-Host "  Service: $($alloySvc.Name) - $($alloySvc.Status)" -ForegroundColor $(if($alloySvc.Status -eq 'Running'){'Green'}else{'Red'})

    $svcWmi = Get-WmiObject Win32_Service -Filter "Name='Alloy'" -ErrorAction SilentlyContinue
    if ($svcWmi) {
        Write-Host "  Path: $($svcWmi.PathName)" -ForegroundColor Cyan
        Write-Host "  StartMode: $($svcWmi.StartMode)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  Service: NOT FOUND" -ForegroundColor Red
}

# Check paths
$alloyPaths = @(
    "C:\Program Files\GrafanaLabs\Alloy\alloy-windows-amd64.exe",
    "C:\ProgramData\GrafanaLabs\Alloy\config.alloy"
)
Write-Host "  Checking paths:" -ForegroundColor Gray
foreach ($p in $alloyPaths) {
    $exists = Test-Path $p
    $color = if ($exists) { "Green" } else { "Red" }
    Write-Host "    $p : $exists" -ForegroundColor $color
}

# Try to get error from Event Log
Write-Host "  Recent errors:" -ForegroundColor Gray
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 5 -ErrorAction SilentlyContinue |
              Where-Object { $_.Message -like "*Alloy*" -or $_.ProviderName -like "*Alloy*" }
    if ($events) {
        foreach ($e in $events) {
            Write-Host "    [$($e.TimeCreated)] $($e.Message.Substring(0, [Math]::Min(100, $e.Message.Length)))..." -ForegroundColor Red
        }
    } else {
        Write-Host "    No recent Alloy errors in Application log" -ForegroundColor Gray
    }
} catch {
    Write-Host "    Cannot read event log" -ForegroundColor Gray
}

# Test config syntax if alloy exists
$alloyExe = "C:\Program Files\GrafanaLabs\Alloy\alloy-windows-amd64.exe"
$alloyConfig = "C:\ProgramData\GrafanaLabs\Alloy\config.alloy"
if ((Test-Path $alloyExe) -and (Test-Path $alloyConfig)) {
    Write-Host "  Testing config syntax..." -ForegroundColor Gray
    try {
        $result = & $alloyExe fmt $alloyConfig 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Config syntax: OK" -ForegroundColor Green
        } else {
            Write-Host "    Config error: $result" -ForegroundColor Red
        }
    } catch {
        Write-Host "    Cannot test config: $_" -ForegroundColor Red
    }
}

Write-Host ""

# =============================================================================
# 3. OSQUERY
# =============================================================================
Write-Host "=== OSQUERY ===" -ForegroundColor Yellow

$osquerySvc = Get-Service -Name "osqueryd" -ErrorAction SilentlyContinue
if ($osquerySvc) {
    Write-Host "  Service: $($osquerySvc.Name) - $($osquerySvc.Status)" -ForegroundColor $(if($osquerySvc.Status -eq 'Running'){'Green'}else{'Red'})

    $svcWmi = Get-WmiObject Win32_Service -Filter "Name='osqueryd'" -ErrorAction SilentlyContinue
    if ($svcWmi) {
        Write-Host "  Path: $($svcWmi.PathName)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  Service: NOT FOUND" -ForegroundColor Red
}

# Search for osquery in common locations
$osquerySearchPaths = @(
    "C:\Program Files\osquery",
    "C:\ProgramData\osquery",
    "C:\Program Files (x86)\osquery"
)

Write-Host "  Searching for osqueryd.exe:" -ForegroundColor Gray
$foundOsquery = $false
foreach ($base in $osquerySearchPaths) {
    if (Test-Path $base) {
        $exe = Get-ChildItem -Path $base -Filter "osqueryd.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exe) {
            Write-Host "    FOUND: $($exe.FullName)" -ForegroundColor Green
            $foundOsquery = $true
        }
    }
}

# Also search Program Files root
$pfSearch = Get-ChildItem "C:\Program Files" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*osquery*" }
if ($pfSearch) {
    foreach ($dir in $pfSearch) {
        Write-Host "    Directory found: $($dir.FullName)" -ForegroundColor Cyan
        $exe = Get-ChildItem -Path $dir.FullName -Filter "osqueryd.exe" -Recurse -ErrorAction SilentlyContinue
        if ($exe) {
            Write-Host "    FOUND: $($exe.FullName)" -ForegroundColor Green
            $foundOsquery = $true
        }
    }
}

if (-not $foundOsquery) {
    Write-Host "    osqueryd.exe NOT FOUND anywhere" -ForegroundColor Red

    # Check if MSI installed something
    Write-Host "  Checking installed programs:" -ForegroundColor Gray
    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -like "*osquery*" }
    if ($installed) {
        Write-Host "    Found in registry: $($installed.DisplayName)" -ForegroundColor Cyan
        Write-Host "    InstallLocation: $($installed.InstallLocation)" -ForegroundColor Cyan
    } else {
        Write-Host "    osquery NOT in installed programs" -ForegroundColor Red
    }
}

# Check osquery logs
$osqueryLog = "C:\Program Files\osquery\osqueryd.results.log"
if (Test-Path $osqueryLog) {
    Write-Host "  Recent log entries:" -ForegroundColor Gray
    Get-Content $osqueryLog -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
}

Write-Host ""

# =============================================================================
# 4. NETWORK CONNECTIVITY
# =============================================================================
Write-Host "=== NETWORK ===" -ForegroundColor Yellow

$targets = @(
    @{Name="Loki"; Host="10.0.1.2"; Port=3100},
    @{Name="FleetDM"; Host="10.0.1.2"; Port=8080}
)

foreach ($t in $targets) {
    Write-Host "  Testing $($t.Name) ($($t.Host):$($t.Port))..." -ForegroundColor Gray
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($t.Host, $t.Port)
        if ($tcp.Connected) {
            Write-Host "    Connected: OK" -ForegroundColor Green
            $tcp.Close()
        }
    } catch {
        Write-Host "    Connection FAILED: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Diagnostics Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Copy output and send to admin for analysis" -ForegroundColor Yellow
Write-Host ""
