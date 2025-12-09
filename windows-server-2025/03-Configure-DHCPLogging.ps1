<#
.SYNOPSIS
    Налаштування розширеного логування DHCP сервера.

.DESCRIPTION
    Активує детальне логування DHCP сервера:
    - Audit logging
    - DHCP database logging
    - Event log налаштування
    - Відстеження оренди IP адрес

.EXAMPLE
    .\03-Configure-DHCPLogging.ps1

.NOTES
    Запускати на DHCP сервері
    Requires administrator rights
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
Write-Host "  DHCP Server Logging Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Verification DHCP сервісу
# =============================================================================
$dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
if (-not $dhcpService) {
    Write-Log "DHCP Server сервіс не знайдено" -Level Error
    Write-Log "Встановіть роль DHCP Server" -Level Info
    exit 1
}

Write-Log "DHCP Server знайдено: $($dhcpService.Status)" -Level Success

# =============================================================================
# Увімкнення DHCP Audit Logging
# =============================================================================
Write-Log "Увімкнення DHCP Audit Logging..." -Level Info

try {
    # Увімкнення аудиту через реєстр
    $dhcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters"

    # Audit logging
    Set-ItemProperty -Path $dhcpParams -Name "ActivityLogFlag" -Value 1 -Type DWord -Force

    # Детальне логування
    Set-ItemProperty -Path $dhcpParams -Name "DhcpLogLevel" -Value 0xFF -Type DWord -Force

    Write-Log "DHCP Audit Logging увімкнено" -Level Success
} catch {
    Write-Log "Помилка налаштування реєстру: $_" -Level Error
}

# =============================================================================
# Налаштування через PowerShell DHCP module
# =============================================================================
Write-Log "Налаштування DHCP через PowerShell..." -Level Info

try {
    Import-Module DhcpServer -ErrorAction Stop

    # Увімкнення аудиту
    Set-DhcpServerAuditLog -Enable $true -Path "C:\Windows\System32\dhcp"

    # Збільшення кількості днів зберігання логів
    Set-DhcpServerAuditLog -DiskCheckInterval 50 -MaxMBFileSize 70

    Write-Log "DHCP PowerShell налаштування застосовано" -Level Success

    # Отримання поточних налаштувань
    $auditSettings = Get-DhcpServerAuditLog
    Write-Log "Audit Path: $($auditSettings.Path)" -Level Info
    Write-Log "Audit Enabled: $($auditSettings.Enable)" -Level Info

} catch {
    Write-Log "Помилка DHCP PowerShell: $_" -Level Warning
    Write-Log "Налаштування через реєстр буде використано" -Level Info
}

# =============================================================================
# Event Log налаштування
# =============================================================================
Write-Log "Налаштування DHCP Event Log..." -Level Info

try {
    # Microsoft-Windows-DHCP-Server/Operational
    wevtutil sl "Microsoft-Windows-DHCP-Server/Operational" /e:true /ms:134217728  # 128 MB

    # Microsoft-Windows-DHCP-Server/FilterNotifications
    wevtutil sl "Microsoft-Windows-DHCP-Server/FilterNotifications" /e:true /ms:67108864  # 64 MB

    Write-Log "DHCP Event Logs налаштовано" -Level Success
} catch {
    Write-Log "Помилка налаштування Event Log: $_" -Level Warning
}

# =============================================================================
# Creating directory for logs
# =============================================================================
$dhcpLogDir = "C:\Windows\System32\dhcp"
if (-not (Test-Path $dhcpLogDir)) {
    New-Item -ItemType Directory -Path $dhcpLogDir -Force | Out-Null
}

# Налаштування прав доступу
$acl = Get-Acl $dhcpLogDir
$permission = "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl -Path $dhcpLogDir -AclObject $acl

Write-Log "DHCP Log директорія: $dhcpLogDir" -Level Info

# =============================================================================
# Restart DHCP сервісу
# =============================================================================
Write-Log "Restart DHCP сервісу..." -Level Info

try {
    Restart-Service -Name DHCPServer -Force
    Start-Sleep -Seconds 5

    $dhcpService = Get-Service -Name DHCPServer
    if ($dhcpService.Status -eq "Running") {
        Write-Log "DHCP сервіс перезапущено" -Level Success
    } else {
        Write-Log "DHCP сервіс не запустився" -Level Error
    }
} catch {
    Write-Log "Помилка перезапуску: $_" -Level Error
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DHCP Logging Configuration Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "DHCP Audit Log файли:" -ForegroundColor Cyan
Write-Host "  Directory: $dhcpLogDir"
Write-Host "  Формат: DhcpSrvLog-<Day>.log"
Write-Host ""
Write-Host "Важливі DHCP Event IDs:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Lease Events:" -ForegroundColor Cyan
Write-Host "  10 - New IP address leased"
Write-Host "  11 - Lease renewed"
Write-Host "  12 - Lease released"
Write-Host "  13 - IP address found in use (conflict)"
Write-Host "  14 - Lease expired"
Write-Host "  15 - Lease deleted"
Write-Host "  17 - Lease denied"
Write-Host "  18 - Lease expired and deleted"
Write-Host ""
Write-Host "DHCP Attacks (Security):" -ForegroundColor Red
Write-Host "  20 - BOOTP request"
Write-Host "  24 - Cleanup started"
Write-Host "  25 - Cleanup finished"
Write-Host "  30 - DNS update request"
Write-Host "  31 - DNS update failed"
Write-Host "  32 - DNS update successful"
Write-Host "  50+ - Rogue DHCP detection"
Write-Host ""
Write-Host "Формат DHCP Audit Log:" -ForegroundColor Yellow
Write-Host "  ID,Date,Time,Description,IP Address,Host Name,MAC Address"
Write-Host ""
Write-Host "Promtail файл для DHCP логів:" -ForegroundColor Yellow
Write-Host '  Додайте job для парсингу C:\Windows\System32\dhcp\DhcpSrvLog-*.log'
Write-Host ""
