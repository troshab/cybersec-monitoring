<#
.SYNOPSIS
    Basic protection (hardening) Windows 11 client.

.DESCRIPTION
    Applies basic security settings for Windows 11:
    - Configuring Windows Firewall
    - Disabling dangerous services
    - Configuring SMB
    - Pass-the-hash protection
    - Blocking LLMNR/NetBIOS

.EXAMPLE
    .\02-Harden-Client.ps1

.NOTES
    Run as administrator
    Before applying, make sure it will not break applications
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipFirewall,
    [switch]$SkipSMB
)

$ErrorActionPreference = "Continue"

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
Write-Host "  Windows 11 Client Hardening" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Windows Firewall
# =============================================================================
if (-not $SkipFirewall) {
    Write-Log "Configuring Windows Firewall..." -Level Info

    # Enabling Firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # Blocking incoming connections by default
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow

    # Enabling logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384

    Write-Log "Windows Firewall configured" -Level Success

    # Blocking NetBIOS via Firewall
    Write-Log "Blocking NetBIOS..." -Level Info

    $netbiosRules = @(
        @{Name = "Block NetBIOS-NS UDP 137"; Protocol = "UDP"; LocalPort = 137},
        @{Name = "Block NetBIOS-DGM UDP 138"; Protocol = "UDP"; LocalPort = 138},
        @{Name = "Block NetBIOS-SSN TCP 139"; Protocol = "TCP"; LocalPort = 139}
    )

    foreach ($rule in $netbiosRules) {
        Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Inbound `
            -Protocol $rule.Protocol `
            -LocalPort $rule.LocalPort `
            -Action Block `
            -Profile Domain,Private,Public | Out-Null
    }

    Write-Log "NetBIOS blocked" -Level Success
} else {
    Write-Log "Firewall skipped (-SkipFirewall)" -Level Warning
}

# =============================================================================
# Disabling dangerous services
# =============================================================================
Write-Log "Disabling dangerous services..." -Level Info

$dangerousServices = @(
    @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"},
    @{Name = "lltdsvc"; DisplayName = "Link-Layer Topology Discovery Mapper"},
    @{Name = "SSDPSRV"; DisplayName = "SSDP Discovery"},
    @{Name = "upnphost"; DisplayName = "UPnP Device Host"},
    @{Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Network Sharing"},
    @{Name = "XboxGipSvc"; DisplayName = "Xbox Accessory Management Service"},
    @{Name = "XblAuthManager"; DisplayName = "Xbox Live Auth Manager"},
    @{Name = "XblGameSave"; DisplayName = "Xbox Live Game Save"},
    @{Name = "XboxNetApiSvc"; DisplayName = "Xbox Live Networking Service"}
)

foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled: $($svc.DisplayName)" -Level Success
        }
    } catch {
        # Service might not exist
    }
}

# =============================================================================
# SMB Hardening
# =============================================================================
if (-not $SkipSMB) {
    Write-Log "Configuring SMB..." -Level Info

    # Disabling SMBv1 (deprecated, vulnerable)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Write-Log "SMBv1 disabled" -Level Success
    } catch {
        Write-Log "SMBv1 already disabled or unavailable" -Level Warning
    }

    # SMB signing (relay attack protection)
    try {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        Write-Log "SMB signing увімкнено" -Level Success
    } catch {
        Write-Log "Помилка налаштування SMB signingу" -Level Warning
    }

    # SMB encryption
    try {
        Set-SmbServerConfiguration -EncryptData $true -Force
        Write-Log "SMB encryption увімкнено" -Level Success
    } catch {
        Write-Log "Помилка налаштування SMB encryption" -Level Warning
    }
} else {
    Write-Log "SMB skipped (-SkipSMB)" -Level Warning
}

# =============================================================================
# LLMNR вимкнення (Responder attack mitigation)
# =============================================================================
Write-Log "Disabling LLMNR..." -Level Info

$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force

Write-Log "LLMNR disabled" -Level Success

# =============================================================================
# NetBIOS вимкнення на всіх адаптерах
# =============================================================================
Write-Log "Disabling NetBIOS over TCP/IP..." -Level Info

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
}

Write-Log "NetBIOS disabled on all adapters" -Level Success

# =============================================================================
# Pass-the-Hash protection
# =============================================================================
Write-Log "Configuring Pass-the-Hash protection..." -Level Info

$pthSettings = @(
    # Restricting WDigest (plain-text passwords in memory)
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Name = "UseLogonCredential"
        Value = 0
        Type = "DWord"
    },
    # LSA protection
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RunAsPPL"
        Value = 1
        Type = "DWord"
    },
    # Disabling LM hash storage
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "NoLMHash"
        Value = 1
        Type = "DWord"
    },
    # Restricting anonymous access
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RestrictAnonymous"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RestrictAnonymousSAM"
        Value = 1
        Type = "DWord"
    },
    # Credential Guard prep (if supported)
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        Name = "EnableVirtualizationBasedSecurity"
        Value = 1
        Type = "DWord"
    }
)

foreach ($setting in $pthSettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
        Write-Log "Set: $($setting.Name)" -Level Success
    } catch {
        Write-Log "Error: $($setting.Name)" -Level Warning
    }
}

# =============================================================================
# UAC посилення
# =============================================================================
Write-Log "Strengthening UAC..." -Level Info

$uacSettings = @(
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "ConsentPromptBehaviorAdmin"
        Value = 2  # Prompt for credentials
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "ConsentPromptBehaviorUser"
        Value = 0  # Automatically deny
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableLUA"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "PromptOnSecureDesktop"
        Value = 1
        Type = "DWord"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "FilterAdministratorToken"
        Value = 1
        Type = "DWord"
    }
)

foreach ($setting in $uacSettings) {
    try {
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
    } catch {
        Write-Log "UAC error: $($setting.Name)" -Level Warning
    }
}

Write-Log "UAC strengthened" -Level Success

# =============================================================================
# RDP обмеження
# =============================================================================
Write-Log "Configuring RDP security..." -Level Info

# NLA (Network Level Authentication)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force

# Minimum encryption level
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force

# Disabling CredSSP Oracle Remediation (protection from CVE-2018-0886)
$credsspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $credsspPath)) {
    New-Item -Path $credsspPath -Force | Out-Null
}
Set-ItemProperty -Path $credsspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -Force

Write-Log "RDP configured (NLA enabled)" -Level Success

# =============================================================================
# Windows Defender посилення
# =============================================================================
Write-Log "Strengthening Windows Defender..." -Level Info

try {
    # Enabling real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

    # PUA protection
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue

    # Behavior monitoring
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue

    # Block at first sight
    Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue

    # Cloud protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue

    # Attack Surface Reduction Rules
    $asrRules = @{
        # Block executable content from email client and webmail
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1
        # Block all Office applications from creating child processes
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
        # Block Office applications from creating executable content
        "3B576869-A4EC-4529-8536-B80A7769E899" = 1
        # Block Office applications from injecting code
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
        # Block JavaScript or VBScript from launching downloaded executable content
        "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
        # Block execution of potentially obfuscated scripts
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
        # Block Win32 API calls from Office macros
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1
        # Block credential stealing from LSASS
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
        # Block untrusted and unsigned processes from USB
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
        # Block process creations from PSExec and WMI commands
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1
    }

    foreach ($rule in $asrRules.GetEnumerator()) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value -ErrorAction SilentlyContinue
    }

    Write-Log "Windows Defender strengthened (ASR rules enabled)" -Level Success
} catch {
    Write-Log "Defender configuration error: $_" -Level Warning
}

# =============================================================================
# Вимкнення автозапуску
# =============================================================================
Write-Log "Disabling autorun..." -Level Info

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Force

Write-Log "Autorun disabled" -Level Success

# =============================================================================
# PowerShell обмеження
# =============================================================================
Write-Log "Configuring PowerShell security..." -Level Info

# Constrained Language Mode for regular users (non-admins)
# This restricts PowerShell script capabilities

# Disabling PowerShell v2 (bypass for AMSI)
try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue
    Write-Log "PowerShell v2 disabled" -Level Success
} catch {
    Write-Log "PowerShell v2 already disabled" -Level Warning
}

# =============================================================================
# Verification результатів
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows 11 Hardening completed!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied:" -ForegroundColor Cyan
Write-Host "  [+] Windows Firewall configured"
Write-Host "  [+] SMBv1 disabled, SMB signing увімкнено"
Write-Host "  [+] LLMNR/NetBIOS disabled"
Write-Host "  [+] Pass-the-Hash protection"
Write-Host "  [+] UAC strengthened"
Write-Host "  [+] RDP NLA enabled"
Write-Host "  [+] Windows Defender ASR rules"
Write-Host "  [+] Autorun disabled"
Write-Host "  [+] PowerShell v2 disabled"
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - Reboot recommended"
Write-Host "  - Check network application functionality"
Write-Host "  - Some old programs may not work"
Write-Host ""

# Verification
Write-Host "Verification:" -ForegroundColor Cyan
$firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
foreach ($profile in $firewallStatus) {
    $status = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
    Write-Host "  Firewall $($profile.Name): $status"
}

$smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Write-Host "  SMBv1: $(if($smb1.EnableSMB1Protocol){'Enabled (WARNING!)'}else{'Disabled'})"
Write-Host ""
