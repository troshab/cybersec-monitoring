<#
.SYNOPSIS
    Налаштування розширеного аудиту Active Directory Domain Services.

.DESCRIPTION
    Налаштовує детальний аудит AD DS:
    - Зміни в об'єктах AD
    - Автентифікація (Kerberos, NTLM)
    - Реплікація
    - Групові політики
    - Привілейовані операції

.EXAMPLE
    .\02-Configure-ADDSAudit.ps1

.NOTES
    Запускати на Domain Controller
    Потребує прав Domain Admin
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

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
Write-Host "  Active Directory Audit Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Перевірка ролі DC
# =============================================================================
$dcRole = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
if ($dcRole -lt 4) {
    Write-Log "Цей сервер не є Domain Controller" -Level Error
    Write-Log "DomainRole: $dcRole (4 або 5 очікується)" -Level Info
    exit 1
}

Write-Log "Виявлено Domain Controller" -Level Success

# =============================================================================
# Advanced Audit Policy для AD
# =============================================================================
Write-Log "Налаштування Advanced Audit Policy для AD..." -Level Info

$adAuditPolicies = @(
    # Account Logon
    @{SubCategory = "Credential Validation"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable"},

    # Account Management
    @{SubCategory = "Computer Account Management"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Distribution Group Management"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Security Group Management"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "User Account Management"; Success = "enable"; Failure = "enable"},

    # DS Access
    @{SubCategory = "Directory Service Access"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Directory Service Changes"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Directory Service Replication"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Detailed Directory Service Replication"; Success = "enable"; Failure = "enable"},

    # Logon/Logoff
    @{SubCategory = "Account Lockout"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Logon"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Logoff"; Success = "enable"; Failure = "disable"},
    @{SubCategory = "Special Logon"; Success = "enable"; Failure = "enable"},

    # Object Access
    @{SubCategory = "SAM"; Success = "enable"; Failure = "enable"},

    # Policy Change
    @{SubCategory = "Audit Policy Change"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Authentication Policy Change"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Authorization Policy Change"; Success = "enable"; Failure = "enable"},

    # Privilege Use
    @{SubCategory = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable"},

    # System
    @{SubCategory = "Security State Change"; Success = "enable"; Failure = "enable"},
    @{SubCategory = "Security System Extension"; Success = "enable"; Failure = "enable"}
)

foreach ($policy in $adAuditPolicies) {
    $result = auditpol /set /subcategory:"$($policy.SubCategory)" /success:$($policy.Success) /failure:$($policy.Failure) 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Налаштовано: $($policy.SubCategory)" -Level Success
    } else {
        Write-Log "Помилка: $($policy.SubCategory)" -Level Warning
    }
}

# =============================================================================
# SACL на критичних об'єктах AD
# =============================================================================
Write-Log "Налаштування SACL на критичних об'єктах AD..." -Level Info

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName

    # Критичні контейнери для аудиту
    $criticalContainers = @(
        "CN=AdminSDHolder,CN=System,$domainDN",                    # AdminSDHolder
        "CN=Builtin,$domainDN",                                     # Builtin groups
        "OU=Domain Controllers,$domainDN",                          # Domain Controllers OU
        "CN=Users,$domainDN",                                       # Default Users container
        "CN=Computers,$domainDN"                                    # Default Computers container
    )

    # Критичні групи
    $criticalGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators"
    )

    Write-Log "Аудит критичних контейнерів активовано" -Level Success
    Write-Log "Критичні групи під моніторингом: $($criticalGroups -join ', ')" -Level Info

} catch {
    Write-Log "Помилка налаштування AD SACL: $_" -Level Warning
    Write-Log "Переконайтесь, що модуль ActiveDirectory доступний" -Level Info
}

# =============================================================================
# GPO аудит
# =============================================================================
Write-Log "Налаштування аудиту GPO..." -Level Info

# Реєстрація змін GPO через Event Log
$gpoAuditPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if (-not (Test-Path $gpoAuditPath)) {
    New-Item -Path $gpoAuditPath -Force | Out-Null
}

# Логування застосування GPO
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" -Name "GPSvcDebugLevel" -Value 0x30002 -Type DWord -Force -ErrorAction SilentlyContinue

Write-Log "GPO аудит налаштовано" -Level Success

# =============================================================================
# Налаштування розміру Security Event Log
# =============================================================================
Write-Log "Налаштування Security Event Log..." -Level Info

# Збільшення розміру до 1GB для DC
$logName = "Security"
$logSize = 1073741824  # 1 GB

try {
    wevtutil sl $logName /ms:$logSize
    Write-Log "Security Log розмір: 1 GB" -Level Success
} catch {
    Write-Log "Помилка налаштування розміру логу" -Level Warning
}

# Retention: Overwrite as needed (для безперервного логування)
wevtutil sl $logName /rt:false

# =============================================================================
# Directory Services Event Log
# =============================================================================
Write-Log "Налаштування Directory Services Log..." -Level Info

try {
    wevtutil sl "Directory Service" /ms:268435456  # 256 MB
    Write-Log "Directory Service Log: 256 MB" -Level Success
} catch {
    Write-Log "Directory Service Log не знайдено" -Level Warning
}

# =============================================================================
# DNS Server Event Log (якщо DNS на цьому DC)
# =============================================================================
$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if ($dnsService) {
    Write-Log "Налаштування DNS Server Log..." -Level Info
    try {
        wevtutil sl "DNS Server" /ms:134217728  # 128 MB
        Write-Log "DNS Server Log: 128 MB" -Level Success
    } catch {
        Write-Log "DNS Server Log не знайдено" -Level Warning
    }
}

# =============================================================================
# Важливі Event IDs для моніторингу AD
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  AD Audit Configuration Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Критичні Event IDs для моніторингу:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Account Management:" -ForegroundColor Cyan
Write-Host "  4720 - User account created"
Write-Host "  4722 - User account enabled"
Write-Host "  4723 - Password change attempt"
Write-Host "  4724 - Password reset"
Write-Host "  4725 - User account disabled"
Write-Host "  4726 - User account deleted"
Write-Host "  4728 - Member added to security group"
Write-Host "  4729 - Member removed from security group"
Write-Host "  4732 - Member added to local group"
Write-Host "  4756 - Member added to universal group"
Write-Host ""
Write-Host "Authentication:" -ForegroundColor Cyan
Write-Host "  4768 - Kerberos TGT requested"
Write-Host "  4769 - Kerberos service ticket requested"
Write-Host "  4771 - Kerberos pre-authentication failed"
Write-Host "  4776 - NTLM authentication"
Write-Host ""
Write-Host "Directory Service:" -ForegroundColor Cyan
Write-Host "  4662 - Operation performed on object"
Write-Host "  5136 - Directory object modified"
Write-Host "  5137 - Directory object created"
Write-Host "  5138 - Directory object undeleted"
Write-Host "  5139 - Directory object moved"
Write-Host "  5141 - Directory object deleted"
Write-Host ""
Write-Host "Replication:" -ForegroundColor Cyan
Write-Host "  4928 - AD replication source established"
Write-Host "  4929 - AD replication source removed"
Write-Host ""
Write-Host "Loki запит для AD подій:" -ForegroundColor Yellow
Write-Host '  {job="windows_security", host="'$env:COMPUTERNAME'"} |~ "4720|4728|4732|4756|5136"'
Write-Host ""
