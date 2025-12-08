# Incident Response - Evidence Collection

Scripts for collecting forensic evidence to submit to CERT-UA.

## Windows: KAPE-style Collection

**KAPE** (Kroll Artifact Parser and Extractor) is the industry standard for Windows forensic collection.

### Quick Collection (our script)
```powershell
# Run as Administrator
.\windows\Collect-Evidence.ps1
```

### Full KAPE Collection
1. Download KAPE from https://www.kroll.com/kape
2. Extract to USB drive
3. Run: `kape.exe --tsource C: --tdest E:\Evidence --target !SANS_Triage`

## Linux: UAC Collection

**UAC** (Unix-like Artifacts Collector) is the standard for Linux/Unix forensics.

### Quick Collection (our script)
```bash
# Run as root
sudo ./linux/collect-evidence.sh
```

### Full UAC Collection
1. Download UAC from https://github.com/tclahr/uac
2. Run: `./uac -p full /path/to/output`

## What Gets Collected

### Windows
- Event Logs (Security, System, PowerShell, Sysmon)
- Prefetch files
- Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY)
- Browser history
- Scheduled tasks
- Services
- Network connections
- Running processes
- Recent files (LNK, Jump Lists)

### Linux
- Auth logs (/var/log/auth.log, secure)
- Syslog
- Audit logs
- Cron jobs
- User histories (.bash_history)
- Network connections
- Running processes
- Installed packages
- SSH keys and authorized_keys

## Submitting to CERT-UA

1. **Encrypt** the evidence archive:
   ```bash
   gpg -c evidence_archive.zip
   ```

2. **Contact CERT-UA**:
   - Email: cert@cert.gov.ua
   - Phone: +380 44 281 88 25
   - Web: https://cert.gov.ua

3. **Provide**:
   - Incident description
   - Timeline of events
   - Affected systems list
   - Evidence archive (encrypted)
   - Encryption password (via phone)

## Chain of Custody

Always document:
- Who collected the evidence
- When (date/time with timezone)
- From which system (hostname, IP, serial number)
- Hash of the archive (SHA256)
- Storage location

## Important Notes

- Run collection ASAP after incident detection
- Do NOT shut down the system before collection
- Collect volatile data first (processes, network connections)
- Preserve original timestamps
- Store evidence on external media
- Calculate and record hashes immediately
