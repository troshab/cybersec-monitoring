<#
.SYNOPSIS
    Налаштування розширеного логування DNS сервера.

.DESCRIPTION
    Активує детальне логування DNS сервера:
    - DNS Analytical logging
    - DNS Debug logging
    - Query logging
    - DNS Audit events

.EXAMPLE
    .\04-Configure-DNSLogging.ps1

.NOTES
    Запускати на DNS сервері
    Потребує прав адміністратора
    Аналітичне логування може збільшити навантаження
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$EnableAnalytical,
    [switch]$EnableDebug
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
Write-Host "  DNS Server Logging Configuration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# Перевірка DNS сервісу
# =============================================================================
$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if (-not $dnsService) {
    Write-Log "DNS Server сервіс не знайдено" -Level Error
    Write-Log "Встановіть роль DNS Server" -Level Info
    exit 1
}

Write-Log "DNS Server знайдено: $($dnsService.Status)" -Level Success

# =============================================================================
# DNS Server Event Log
# =============================================================================
Write-Log "Налаштування DNS Event Log..." -Level Info

try {
    # DNS Server operational log
    wevtutil sl "DNS Server" /ms:268435456  # 256 MB
    wevtutil sl "DNS Server" /rt:false

    Write-Log "DNS Server Event Log: 256 MB" -Level Success
} catch {
    Write-Log "Помилка налаштування Event Log: $_" -Level Warning
}

# =============================================================================
# DNS Analytical Log (детальне логування запитів)
# =============================================================================
if ($EnableAnalytical) {
    Write-Log "Увімкнення DNS Analytical Log..." -Level Info

    try {
        # Увімкнення аналітичного логу
        wevtutil sl "Microsoft-Windows-DNS-Server/Analytical" /e:true /ms:536870912  # 512 MB

        Write-Log "DNS Analytical Log увімкнено (512 MB)" -Level Success
        Write-Log "УВАГА: Аналітичне логування створює багато даних!" -Level Warning
    } catch {
        Write-Log "Помилка увімкнення Analytical Log: $_" -Level Warning
    }
} else {
    Write-Log "DNS Analytical Log пропущено (використайте -EnableAnalytical)" -Level Info
}

# =============================================================================
# DNS Debug Logging
# =============================================================================
if ($EnableDebug) {
    Write-Log "Увімкнення DNS Debug Logging..." -Level Info

    try {
        Import-Module DnsServer -ErrorAction Stop

        # Увімкнення debug logging
        Set-DnsServerDiagnostics -All $true

        # Або вибіркове логування
        Set-DnsServerDiagnostics -Queries $true `
            -Answers $true `
            -Notifications $true `
            -Update $true `
            -QuestionTransactions $true `
            -UnmatchedResponse $true `
            -SendPackets $true `
            -ReceivePackets $true `
            -TcpPackets $true `
            -UdpPackets $true `
            -FullPackets $false `
            -FilterIPAddressList @() `
            -EventLogLevel 4 `
            -UseSystemEventLog $true `
            -EnableLoggingToFile $true `
            -EnableLogFileRollover $true `
            -LogFilePath "C:\Windows\System32\dns\dns.log" `
            -MaxMBFileSize 500

        Write-Log "DNS Debug Logging увімкнено" -Level Success

    } catch {
        Write-Log "Помилка DNS Debug: $_" -Level Warning

        # Альтернатива через dnscmd
        Write-Log "Спроба через dnscmd..." -Level Info
        dnscmd /config /LogLevel 0xFFFF
        dnscmd /config /LogFilePath "C:\Windows\System32\dns\dns.log"
        dnscmd /config /LogFileMaxSize 500000000
    }
} else {
    Write-Log "DNS Debug Logging пропущено (використайте -EnableDebug)" -Level Info
}

# =============================================================================
# DNS Audit Policy
# =============================================================================
Write-Log "Налаштування DNS Audit Policy..." -Level Info

try {
    Import-Module DnsServer -ErrorAction Stop

    # Отримання поточних налаштувань
    $currentDiag = Get-DnsServerDiagnostics

    # Мінімальне логування для безпеки (без повного debug)
    Set-DnsServerDiagnostics -EventLogLevel 4  # Verbose
    Set-DnsServerDiagnostics -UseSystemEventLog $true

    Write-Log "DNS Event Logging налаштовано" -Level Success

} catch {
    Write-Log "Помилка DnsServer module: $_" -Level Warning
}

# =============================================================================
# DNS Query Logging через ETW
# =============================================================================
Write-Log "Налаштування DNS Query Logging через ETW..." -Level Info

$dnsQueryLogging = @"
<?xml version="1.0" encoding="utf-8"?>
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-DNS-Server/Analytical">
    <Select Path="Microsoft-Windows-DNS-Server/Analytical">*</Select>
  </Query>
</QueryList>
"@

# Створення директорії для DNS логів
$dnsLogDir = "C:\Windows\System32\dns"
if (-not (Test-Path $dnsLogDir)) {
    New-Item -ItemType Directory -Path $dnsLogDir -Force | Out-Null
}

Write-Log "DNS Log директорія: $dnsLogDir" -Level Info

# =============================================================================
# Реєстрація важливих Event IDs
# =============================================================================
Write-Log "Налаштування моніторингу критичних DNS подій..." -Level Info

# DNS Server Events для моніторингу
$dnsEvents = @{
    # Zone events
    "1" = "DNS Server started"
    "2" = "DNS Server stopped"
    "3" = "DNS Server zone loaded"
    "4" = "DNS Server zone deleted"

    # Query events (Analytical)
    "256" = "DNS query received"
    "257" = "DNS query response"

    # Security events
    "541" = "DNS zone transfer started"
    "542" = "DNS zone transfer completed"
    "543" = "DNS zone transfer failed"

    # DNSSEC events
    "7000" = "DNSSEC validation failed"
    "7053" = "DNSSEC trust anchor update"
}

Write-Log "Зареєстровано $($dnsEvents.Count) DNS Event IDs" -Level Success

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DNS Logging Configuration Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Налаштування:" -ForegroundColor Cyan
Write-Host "  DNS Event Log: 256 MB"
Write-Host "  Analytical Log: $(if($EnableAnalytical){'Enabled'}else{'Disabled'})"
Write-Host "  Debug Logging: $(if($EnableDebug){'Enabled'}else{'Disabled'})"
Write-Host "  Log Directory: $dnsLogDir"
Write-Host ""
Write-Host "Важливі DNS Event IDs:" -ForegroundColor Yellow
Write-Host ""
Write-Host "DNS Server Events (Log: DNS Server):" -ForegroundColor Cyan
Write-Host "  1    - DNS Server started"
Write-Host "  2    - DNS Server stopped"
Write-Host "  3    - Zone loaded"
Write-Host "  4    - Zone unloaded"
Write-Host "  6001 - DNS Server started"
Write-Host "  6002 - DNS Server stopped"
Write-Host ""
Write-Host "DNS Analytical Events (Query logging):" -ForegroundColor Cyan
Write-Host "  256 - DNS query received (QUERY_RECEIVED)"
Write-Host "  257 - DNS response sent (RESPONSE_SUCCESS)"
Write-Host "  258 - DNS recursive query"
Write-Host "  259 - DNS response failure"
Write-Host "  260 - Recursive query timeout"
Write-Host ""
Write-Host "DNS Security Events:" -ForegroundColor Red
Write-Host "  541 - Zone transfer initiated"
Write-Host "  542 - Zone transfer successful"
Write-Host "  543 - Zone transfer failed"
Write-Host "  544 - Zone transfer denied"
Write-Host ""
Write-Host "Loki запит для DNS:" -ForegroundColor Yellow
Write-Host '  {job="windows_dns"} |= "QUERY_RECEIVED"'
Write-Host '  {job="windows_dns"} |~ "zone transfer"'
Write-Host ""
Write-Host "УВАГА:" -ForegroundColor Yellow
Write-Host "  - Analytical logging створює великий об'єм даних"
Write-Host "  - Debug logging впливає на продуктивність"
Write-Host "  - Рекомендується для troubleshooting або security analysis"
Write-Host ""
