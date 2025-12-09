<#
.SYNOPSIS
    Basic protection (hardening) Windows Server 2025.

.DESCRIPTION
    Застосовує базові налаштування безпеки для Windows Server:
    - Вимкнення небезпечних протоколів (SMBv1, TLS 1.0/1.1)
    - Configuring Windows Firewall
    - Pass-the-Hash protection
    - Restricting anonymous access
    - Налаштування RDP безпеки

.EXAMPLE
    .\01-Harden-Server.ps1

.NOTES
    Run as administrator
    Some changes require a reboot
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipFirewall,
    [switch]$SkipTLS
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
Write-Host "  Windows Server 2025 Hardening" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# SMB Hardening
# =============================================================================
Write-Log "Configuring SMB..." -Level Info

# Disabling SMBv1
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Write-Log "SMBv1 disabled на сервері" -Level Success
} catch {
    Write-Log "SMBv1 вже вимкнено" -Level Warning
}

# SMB signing (обов'язковий для серверів)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Write-Log "SMB signing увімкнено (обов'язковий)" -Level Success

# SMB encryption
Set-SmbServerConfiguration -EncryptData $true -Force
Write-Log "SMB encryption увімкнено" -Level Success

# Вимкнення SMB компресії (protection from CVE-2020-0796)
Set-SmbServerConfiguration -DisableCompression $true -Force -ErrorAction SilentlyContinue
Write-Log "SMB компресія вимкнена" -Level Success

# =============================================================================
# TLS/SSL Hardening
# =============================================================================
if (-not $SkipTLS) {
    Write-Log "Налаштування TLS/SSL..." -Level Info

    # Вимкнення TLS 1.0
    $tls10Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
    New-Item -Path "$tls10Path\Server" -Force | Out-Null
    New-Item -Path "$tls10Path\Client" -Force | Out-Null
    Set-ItemProperty -Path "$tls10Path\Server" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "$tls10Path\Client" -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Log "TLS 1.0 вимкнено" -Level Success

    # Вимкнення TLS 1.1
    $tls11Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
    New-Item -Path "$tls11Path\Server" -Force | Out-Null
    New-Item -Path "$tls11Path\Client" -Force | Out-Null
    Set-ItemProperty -Path "$tls11Path\Server" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "$tls11Path\Client" -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Log "TLS 1.1 вимкнено" -Level Success

    # Увімкнення TLS 1.2 (явно)
    $tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
    New-Item -Path "$tls12Path\Server" -Force | Out-Null
    New-Item -Path "$tls12Path\Client" -Force | Out-Null
    Set-ItemProperty -Path "$tls12Path\Server" -Name "Enabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "$tls12Path\Client" -Name "Enabled" -Value 1 -Type DWord -Force
    Write-Log "TLS 1.2 увімкнено" -Level Success

    # Увімкнення TLS 1.3
    $tls13Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3"
    New-Item -Path "$tls13Path\Server" -Force | Out-Null
    New-Item -Path "$tls13Path\Client" -Force | Out-Null
    Set-ItemProperty -Path "$tls13Path\Server" -Name "Enabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "$tls13Path\Client" -Name "Enabled" -Value 1 -Type DWord -Force
    Write-Log "TLS 1.3 увімкнено" -Level Success

    # Вимкнення SSL 2.0/3.0
    foreach ($ssl in @("SSL 2.0", "SSL 3.0")) {
        $sslPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ssl"
        New-Item -Path "$sslPath\Server" -Force | Out-Null
        New-Item -Path "$sslPath\Client" -Force | Out-Null
        Set-ItemProperty -Path "$sslPath\Server" -Name "Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "$sslPath\Client" -Name "Enabled" -Value 0 -Type DWord -Force
    }
    Write-Log "SSL 2.0/3.0 вимкнено" -Level Success

    # Вимкнення слабких cipher suites
    $weakCiphers = @(
        "DES 56/56",
        "RC2 40/128",
        "RC2 56/128",
        "RC2 128/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "RC4 128/128",
        "NULL",
        "Triple DES 168"
    )

    foreach ($cipher in $weakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (-not (Test-Path $cipherPath)) {
            New-Item -Path $cipherPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord -Force
    }
    Write-Log "Слабкі шифри вимкнено" -Level Success
} else {
    Write-Log "TLS налаштування пропущено (-SkipTLS)" -Level Warning
}

# =============================================================================
# Windows Firewall
# =============================================================================
if (-not $SkipFirewall) {
    Write-Log "Configuring Windows Firewall..." -Level Info

    # Увімкнення для всіх профілів
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # Заборона вхідних за замовчуванням (крім дозволених)
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block

    # Логування
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 32768

    Write-Log "Windows Firewall configured" -Level Success
} else {
    Write-Log "Firewall skipped (-SkipFirewall)" -Level Warning
}

# =============================================================================
# LLMNR/NetBIOS вимкнення
# =============================================================================
Write-Log "Disabling LLMNR..." -Level Info

$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Write-Log "LLMNR disabled" -Level Success

# NetBIOS на всіх адаптерах
Write-Log "Вимкнення NetBIOS..." -Level Info
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null
}
Write-Log "NetBIOS вимкнено" -Level Success

# =============================================================================
# Pass-the-Hash захист
# =============================================================================
Write-Log "Configuring Pass-the-Hash protection..." -Level Info

$pthSettings = @(
    # WDigest (plain-text паролі)
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0},
    # LSA Protection
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; Value = 1},
    # No LM Hash
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Value = 1},
    # LM Compatibility Level (NTLMv2 only)
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel"; Value = 5},
    # Restrict Anonymous
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1},
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Value = 1},
    # Credential Guard (if supported)
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1},
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 1},
    # LSASS as PPL
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LsaCfgFlags"; Value = 1}
)

foreach ($setting in $pthSettings) {
    try {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
    } catch {
        # Ignore errors for optional settings
    }
}
Write-Log "Захист від PtH налаштовано" -Level Success

# =============================================================================
# RDP Security
# =============================================================================
Write-Log "Configuring RDP security..." -Level Info

# NLA обов'язковий
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force

# Максимальний рівень шифрування
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force

# Security Layer (TLS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord -Force

Write-Log "RDP configured (NLA, TLS)" -Level Success

# =============================================================================
# Небезпечні служби
# =============================================================================
Write-Log "Disabling dangerous services..." -Level Info

$dangerousServices = @(
    "Browser",           # Computer Browser
    "IISADMIN",          # IIS Admin (if not needed)
    "TlntSvr",           # Telnet
    "SNMPTRAP",          # SNMP Trap
    "RemoteRegistry",    # Remote Registry
    "lltdsvc",           # Link-Layer Topology Discovery
    "SSDPSRV",           # SSDP Discovery
    "upnphost"           # UPnP Device Host
)

foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled: $svc" -Level Success
        }
    } catch {
        # Service might not exist
    }
}

# =============================================================================
# PowerShell v2 вимкнення
# =============================================================================
Write-Log "Disabling PowerShell v2..." -Level Info

try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue
    Write-Log "PowerShell v2 disabled" -Level Success
} catch {
    Write-Log "PowerShell v2 already disabled" -Level Warning
}

# =============================================================================
# Windows Remote Management (WinRM) Security
# =============================================================================
Write-Log "Налаштування WinRM безпеки..." -Level Info

try {
    # Увімкнення тільки HTTPS (якщо налаштовано)
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -ErrorAction SilentlyContinue

    # Базова автентифікація вимкнена
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -ErrorAction SilentlyContinue

    # Kerberos увімкнено
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -ErrorAction SilentlyContinue

    # Negotiate увімкнено
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true -ErrorAction SilentlyContinue

    Write-Log "WinRM налаштовано" -Level Success
} catch {
    Write-Log "WinRM налаштування пропущено" -Level Warning
}

# =============================================================================
# Audit Policy посилення
# =============================================================================
Write-Log "Посилення Audit Policy для сервера..." -Level Info

# Додаткові категорії для серверів
$serverAuditCategories = @(
    @{Category = "DS Access"; SubCategory = "Directory Service Access"; Success = "enable"; Failure = "enable"},
    @{Category = "DS Access"; SubCategory = "Directory Service Changes"; Success = "enable"; Failure = "enable"},
    @{Category = "DS Access"; SubCategory = "Directory Service Replication"; Success = "enable"; Failure = "enable"},
    @{Category = "Object Access"; SubCategory = "Detailed File Share"; Success = "enable"; Failure = "enable"},
    @{Category = "Object Access"; SubCategory = "File Share"; Success = "enable"; Failure = "enable"},
    @{Category = "Object Access"; SubCategory = "Removable Storage"; Success = "enable"; Failure = "enable"},
    @{Category = "Policy Change"; SubCategory = "Authorization Policy Change"; Success = "enable"; Failure = "enable"}
)

foreach ($audit in $serverAuditCategories) {
    auditpol /set /subcategory:"$($audit.SubCategory)" /success:$($audit.Success) /failure:$($audit.Failure) 2>$null
}

Write-Log "Audit Policy посилено" -Level Success

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows Server 2025 Hardening завершено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied:" -ForegroundColor Cyan
Write-Host "  [+] SMBv1 disabled, SMB signing обов'язковий"
Write-Host "  [+] TLS 1.0/1.1 вимкнено, TLS 1.2/1.3 увімкнено"
Write-Host "  [+] Windows Firewall configured"
Write-Host "  [+] LLMNR/NetBIOS disabled"
Write-Host "  [+] Pass-the-Hash protection"
Write-Host "  [+] RDP NLA обов'язковий"
Write-Host "  [+] WinRM посилено"
Write-Host "  [+] Audit Policy розширено"
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - Reboot recommended"
Write-Host "  - Перевірте роботу сервісів"
Write-Host "  - TLS зміни можуть вплинути на старі клієнти"
Write-Host ""
