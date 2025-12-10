# Incident Response - Evidence Collection

Professional forensic evidence collection tools for CERT-UA submission.

## Windows: KAPE

**KAPE** (Kroll Artifact Parser and Extractor) is the industry standard for Windows forensic collection.

### Setup
```powershell
# Run as Administrator
.\windows\Install-KAPE.ps1
```

This will:
1. Create directory structure at `C:\Tools\KAPE`
2. Generate collection scripts (Quick, Full, Memory)
3. Provide instructions for downloading KAPE

### Download KAPE
KAPE requires manual download due to licensing:
1. Go to https://www.kroll.com/kape
2. Fill out the form
3. Extract to `C:\Tools\KAPE`
4. Run `kape.exe --sync` to update targets

### Collection
After installing KAPE:
```cmd
cd C:\Tools\KAPE
Collect-QuickTriage.bat     # Fast IR triage (~5-10 min)
Collect-Full.bat            # Comprehensive (~30-60 min)
Collect-WithMemory.bat      # With memory dump
```

Or command line:
```cmd
kape.exe --tsource C: --tdest E:\Evidence --target !SANS_Triage --vhdx EVIDENCE
```

## Linux: UAC

**UAC** (Unix-like Artifacts Collector) is the standard for Linux/Unix forensics.

### Setup & Collection
```bash
# Install UAC
sudo ./linux/install-uac.sh

# Quick IR triage
cd /opt/uac
sudo ./collect-quick.sh /path/to/output

# Full collection
sudo ./collect-full.sh /path/to/output

# With memory (requires AVML/LiME)
sudo ./collect-memory.sh /path/to/output
```

Or direct UAC usage:
```bash
cd /opt/uac
sudo ./uac -p ir_triage /path/to/output   # Quick
sudo ./uac -p full /path/to/output        # Full
```

## What Gets Collected

### Windows (KAPE)
- Event Logs (Security, System, PowerShell, Sysmon)
- Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY)
- Prefetch files
- SRUM database
- Amcache
- Browser artifacts
- Scheduled tasks
- Services
- User artifacts (LNK, Jump Lists, MRU)

### Linux (UAC)
- Auth logs (/var/log/auth.log, secure)
- Syslog, messages
- Audit logs
- Running processes
- Network connections
- Cron jobs
- User histories (.bash_history)
- SSH artifacts
- Installed packages
- Docker/container artifacts

## Submitting to CERT-UA

1. **Calculate hash**:
   ```bash
   sha256sum evidence_archive.tar.gz
   ```

2. **Encrypt** the evidence:
   ```bash
   gpg -c evidence_archive.tar.gz
   ```

3. **Contact CERT-UA**:
   - Email: cert@cert.gov.ua
   - Phone: +380 44 281 88 25
   - Web: https://cert.gov.ua

4. **Provide**:
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

## Resources

- KAPE: https://www.kroll.com/kape
- KAPE Docs: https://ericzimmerman.github.io/KapeDocs/
- UAC: https://github.com/tclahr/uac
- CERT-UA: https://cert.gov.ua
