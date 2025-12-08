# Kali Linux Detection Testing Scripts

Scripts for testing detection capabilities from an attacker's perspective.

## Prerequisites

- Kali Linux (2024.x or later)
- Network access to target systems
- **AUTHORIZATION** to perform security testing

## Scripts Overview

| Script | Description | Triggers |
|--------|-------------|----------|
| `01-network-discovery.sh` | Network scanning and host discovery | Firewall logs, Sysmon 3 |
| `02-port-scanning.sh` | Port scanning techniques | IDS alerts, Sysmon 3 |
| `03-smb-enumeration.sh` | SMB/Windows enumeration | Event 4625, 5140-5145 |
| `04-credential-attacks.sh` | Password spraying, brute force | Event 4625, 4740, 4776 |
| `05-lateral-movement.sh` | PsExec, WMI, WinRM simulation | Event 4624, 4648, Sysmon 1 |
| `06-persistence-simulation.sh` | Persistence techniques | Event 7045, 4698 |
| `run-all-tests.sh` | Execute all tests sequentially | All above |

## Expected Detection Events

### Network Layer
- Firewall connection logs
- IDS/IPS alerts
- Sysmon Event 3 (Network Connection)

### Authentication
- Event 4625: Failed Logon
- Event 4740: Account Lockout
- Event 4776: Credential Validation

### Lateral Movement
- Event 4624: Successful Logon (Type 3, 10)
- Event 4648: Explicit Credentials
- Sysmon Event 1: Process Create

### Persistence
- Event 7045: Service Installed
- Event 4698: Scheduled Task Created
- Event 4697: Security Service Installed

## Usage

```bash
# Make scripts executable
chmod +x *.sh

# Run single test against Windows Server 2025
./01-network-discovery.sh -t 10.0.1.3

# Run all tests against Windows Server
./run-all-tests.sh -t 10.0.1.3

# Run against Windows 11 client
./run-all-tests.sh -t 10.0.1.4 -d 30

# Run with credentials for lateral movement tests
./run-all-tests.sh -t 10.0.1.3 -u monadmin -p 'Mon!123admin'
```

## Safety Notes

1. **ONLY use in authorized test environments**
2. Scripts include safety checks and delays
3. All actions are logged locally
4. Some attacks are simulated, not executed

## Verification in Grafana

After running tests, verify detection in Grafana:

```
# Failed authentication attempts
{job="windows_auth"} |= "4625"

# Network connections from Kali IP
{job="windows_sysmon"} |~ "YOUR_KALI_IP"

# New services created
{job="windows_services"} |= "7045"
```
