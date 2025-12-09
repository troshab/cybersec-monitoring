<#
.SYNOPSIS
    Базове захищення (hardening) Windows 11 клієнта.

.DESCRIPTION
    Застосовує базові налаштування безпеки для Windows 11:
    - Налаштування Windows Firewall
    - Вимкнення небезпечних служб
    - Налаштування SMB
    - Захист від pass-the-hash
    - Блокування LLMNR/NetBIOS

.EXAMPLE
    .\02-Harden-Client.ps1

.NOTES
    Запускати від адміністратора
    Перед застосуванням переконайтесь, що не порушить роботу додатків
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
    Write-Log "Налаштування Windows Firewall..." -Level Info

    # Включення Firewall для всіх профілів
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # Заборона вхідних з'єднань за замовчуванням
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow

    # Включення логування
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384

    Write-Log "Windows Firewall налаштовано" -Level Success

    # Блокування NetBIOS через Firewall
    Write-Log "Блокування NetBIOS..." -Level Info

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

    Write-Log "NetBIOS заблоковано" -Level Success
} else {
    Write-Log "Firewall пропущено (-SkipFirewall)" -Level Warning
}

# =============================================================================
# Вимкнення небезпечних служб
# =============================================================================
Write-Log "Вимкнення небезпечних служб..." -Level Info

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
            Write-Log "Вимкнено: $($svc.DisplayName)" -Level Success
        }
    } catch {
        # Service might not exist
    }
}

# =============================================================================
# SMB Hardening
# =============================================================================
if (-not $SkipSMB) {
    Write-Log "Налаштування SMB..." -Level Info

    # Вимкнення SMBv1 (застарілий, вразливий)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Write-Log "SMBv1 вимкнено" -Level Success
    } catch {
        Write-Log "SMBv1 вже вимкнено або недоступний" -Level Warning
    }

    # SMB підпис (захист від relay атак)
    try {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        Write-Log "SMB підпис увімкнено" -Level Success
    } catch {
        Write-Log "Помилка налаштування SMB підпису" -Level Warning
    }

    # SMB шифрування
    try {
        Set-SmbServerConfiguration -EncryptData $true -Force
        Write-Log "SMB шифрування увімкнено" -Level Success
    } catch {
        Write-Log "Помилка налаштування SMB шифрування" -Level Warning
    }
} else {
    Write-Log "SMB пропущено (-SkipSMB)" -Level Warning
}

# =============================================================================
# LLMNR вимкнення (Responder attack mitigation)
# =============================================================================
Write-Log "Вимкнення LLMNR..." -Level Info

$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force

Write-Log "LLMNR вимкнено" -Level Success

# =============================================================================
# NetBIOS вимкнення на всіх адаптерах
# =============================================================================
Write-Log "Вимкнення NetBIOS over TCP/IP..." -Level Info

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
}

Write-Log "NetBIOS вимкнено на всіх адаптерах" -Level Success

# =============================================================================
# Захист від Pass-the-Hash
# =============================================================================
Write-Log "Налаштування захисту від Pass-the-Hash..." -Level Info

$pthSettings = @(
    # Обмеження WDigest (plain-text паролі в пам'яті)
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Name = "UseLogonCredential"
        Value = 0
        Type = "DWord"
    },
    # LSA захист
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RunAsPPL"
        Value = 1
        Type = "DWord"
    },
    # Вимкнення збереження LM hash
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "NoLMHash"
        Value = 1
        Type = "DWord"
    },
    # Обмеження anonymous доступу
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
    # Credential Guard prep (якщо підтримується)
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
        Write-Log "Встановлено: $($setting.Name)" -Level Success
    } catch {
        Write-Log "Помилка: $($setting.Name)" -Level Warning
    }
}

# =============================================================================
# UAC посилення
# =============================================================================
Write-Log "Посилення UAC..." -Level Info

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
        Write-Log "Помилка UAC: $($setting.Name)" -Level Warning
    }
}

Write-Log "UAC посилено" -Level Success

# =============================================================================
# RDP обмеження
# =============================================================================
Write-Log "Налаштування RDP безпеки..." -Level Info

# NLA (Network Level Authentication)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force

# Мінімальний рівень шифрування
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force

# Вимкнення CredSSP Oracle Remediation (захист від CVE-2018-0886)
$credsspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $credsspPath)) {
    New-Item -Path $credsspPath -Force | Out-Null
}
Set-ItemProperty -Path $credsspPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord -Force

Write-Log "RDP налаштовано (NLA увімкнено)" -Level Success

# =============================================================================
# Windows Defender посилення
# =============================================================================
Write-Log "Посилення Windows Defender..." -Level Info

try {
    # Увімкнення захисту в реальному часі
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

    # PUA захист
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

    Write-Log "Windows Defender посилено (ASR правила увімкнено)" -Level Success
} catch {
    Write-Log "Помилка налаштування Defender: $_" -Level Warning
}

# =============================================================================
# Вимкнення автозапуску
# =============================================================================
Write-Log "Вимкнення автозапуску..." -Level Info

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Force

Write-Log "Автозапуск вимкнено" -Level Success

# =============================================================================
# PowerShell обмеження
# =============================================================================
Write-Log "Налаштування PowerShell безпеки..." -Level Info

# Constrained Language Mode для звичайних користувачів (не адмінів)
# Це обмежує можливості PowerShell скриптів

# Вимкнення PowerShell v2 (bypass для AMSI)
try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue
    Write-Log "PowerShell v2 вимкнено" -Level Success
} catch {
    Write-Log "PowerShell v2 вже вимкнено" -Level Warning
}

# =============================================================================
# Перевірка результатів
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows 11 Hardening завершено!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Застосовано:" -ForegroundColor Cyan
Write-Host "  [+] Windows Firewall налаштовано"
Write-Host "  [+] SMBv1 вимкнено, SMB підпис увімкнено"
Write-Host "  [+] LLMNR/NetBIOS вимкнено"
Write-Host "  [+] Захист від Pass-the-Hash"
Write-Host "  [+] UAC посилено"
Write-Host "  [+] RDP NLA увімкнено"
Write-Host "  [+] Windows Defender ASR правила"
Write-Host "  [+] Автозапуск вимкнено"
Write-Host "  [+] PowerShell v2 вимкнено"
Write-Host ""
Write-Host "ВАЖЛИВО:" -ForegroundColor Yellow
Write-Host "  - Рекомендується перезавантаження"
Write-Host "  - Перевірте роботу мережевих додатків"
Write-Host "  - Деякі старі програми можуть не працювати"
Write-Host ""

# Verification
Write-Host "Перевірка:" -ForegroundColor Cyan
$firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
foreach ($profile in $firewallStatus) {
    $status = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
    Write-Host "  Firewall $($profile.Name): $status"
}

$smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Write-Host "  SMBv1: $(if($smb1.EnableSMB1Protocol){'Enabled (WARNING!)'}else{'Disabled'})"
Write-Host ""
