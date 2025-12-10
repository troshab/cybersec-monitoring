# Quick osquery installer for FleetDM
# Usage: iex ((New-Object Net.WebClient).DownloadString('http://server/Install-FleetOsquery.ps1'))

param(
    [string]$FleetUrl = "10.0.1.2:8080",
    [string]$EnrollSecret = "",
    [string]$OsqueryVersion = "5.12.1"
)

$ErrorActionPreference = "Stop"
Write-Host "=== Installing osquery for FleetDM ===" -ForegroundColor Cyan

# Download osquery
$tempDir = "$env:TEMP\osquery_install"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$msiFile = "$tempDir\osquery.msi"

Write-Host "[*] Downloading osquery v$OsqueryVersion..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = "https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi"
Invoke-WebRequest -Uri $url -OutFile $msiFile -UseBasicParsing

Write-Host "[*] Installing osquery..." -ForegroundColor Yellow
$installArgs = @(
    "/i", $msiFile,
    "/qn",
    "/norestart",
    "TARGETDIR=C:\Program Files\osquery"
)
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "[-] MSI installation failed with code $($proc.ExitCode)" -ForegroundColor Red
    exit 1
}

Write-Host "[+] osquery installed" -ForegroundColor Green

# Configure for FleetDM
$osqueryDir = "C:\Program Files\osquery"
$enrollSecretPath = "$osqueryDir\enroll.secret"
$flagsPath = "$osqueryDir\osquery.flags"
$certPath = "$osqueryDir\fleet.pem"

# Write enroll secret
$EnrollSecret | Out-File -FilePath $enrollSecretPath -Encoding ASCII -NoNewline

# Get certificate (self-signed)
Write-Host "[*] Getting FleetDM certificate..." -ForegroundColor Yellow
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient($FleetUrl.Split(':')[0], $FleetUrl.Split(':')[1])
    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
    $sslStream.AuthenticateAsClient($FleetUrl.Split(':')[0])
    $cert = $sslStream.RemoteCertificate
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $pemContent = "-----BEGIN CERTIFICATE-----`r`n"
    $pemContent += [Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $pemContent += "`r`n-----END CERTIFICATE-----"
    $pemContent | Out-File -FilePath $certPath -Encoding ASCII
    $sslStream.Close()
    $tcpClient.Close()
    Write-Host "[+] Certificate saved" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not get cert, creating empty file" -ForegroundColor Yellow
    "" | Out-File -FilePath $certPath -Encoding ASCII
}

# Write flags
$flags = @"
--tls_hostname=$FleetUrl
--enroll_secret_path=$enrollSecretPath
--tls_server_certs=$certPath
--host_identifier=uuid
--enroll_tls_endpoint=/api/osquery/enroll
--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_refresh=10
--disable_distributed=false
--distributed_plugin=tls
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
--disable_enrollment=false
"@
$flags | Out-File -FilePath $flagsPath -Encoding ASCII

Write-Host "[+] osquery configured for FleetDM" -ForegroundColor Green

# Start service
Write-Host "[*] Starting osqueryd service..." -ForegroundColor Yellow
Stop-Service osqueryd -ErrorAction SilentlyContinue
Start-Sleep 2
Start-Service osqueryd
Start-Sleep 3

$svc = Get-Service osqueryd
Write-Host "[+] osqueryd status: $($svc.Status)" -ForegroundColor Green

Write-Host "=== Done! Host should appear in FleetDM shortly ===" -ForegroundColor Cyan
