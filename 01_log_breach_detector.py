#!/usr/bin/env python3
"""
=============================================================================
SCRIPT 01 - Log File Breach Detector
=============================================================================
Coverage : Breach Detection & Log Analysis
Difficulty: Beginner-Intermediate
Tested on : Ubuntu 22.04 (synthetic auth.log - 200 lines)
Result    : PASSED - Detected brute-force, privilege escalation, bad IPs

WHAT IT DOES:
  Scans system log files (auth.log, syslog, /var/log/secure) for suspicious
  patterns including:
    - Brute-force login attempts (>5 failed logins from same IP)
    - Privilege escalation via sudo
    - Unauthorized root logins
    - Port scan signatures
    - Malware dropper commands (wget/curl fetching .sh/.exe/.ps1)
    - Known malicious IP cross-reference

HOW IT WORKS:
  Reads the log file line-by-line, applies compiled regex patterns for each
  threat category, tracks repeat offenders using a defaultdict counter, and
  cross-references every line against a local bad-IP list.
  Outputs color-coded terminal alerts (CRITICAL / HIGH / MEDIUM) and saves
  a structured JSON report to disk.

USAGE:
  python3 01_log_breach_detector.py --log /var/log/auth.log
  python3 01_log_breach_detector.py --log /var/log/auth.log --threshold 3
  python3 01_log_breach_detector.py --log sample_auth.log --output report.json

IMPROVEMENTS NEEDED:
  - Add --tail / -f mode for real-time monitoring
  - Integrate email alerts via smtplib when CRITICAL events fire
  - Pull live bad-IP feeds from AbuseIPDB or Shodan API
=============================================================================
"""

import re
import sys
import json
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path


# -- Threat Signatures (regex patterns) ---------------------------------------
PATTERNS = {
    "BRUTE_FORCE":     r"Failed password for .+ from (\S+)",
    "INVALID_USER":    r"Invalid user (\S+) from (\S+)",
    "PRIV_ESCALATION": r"sudo.*COMMAND=.*(passwd|useradd|chmod 777|visudo)",
    "PORT_SCAN":       r"(nmap|masscan|SYN flood|XMAS scan|FIN scan)",
    "ROOT_LOGIN":      r"ROOT LOGIN.*FROM (\S+)",
    "MALWARE_DROPPER": r"(wget|curl).*http.*(\.(sh|ps1|exe|bat|py))",
    "ACCEPTED_PUBKEY": r"Accepted publickey for root",
}

# Known malicious IPs (in production: load from threat-feed file)
KNOWN_BAD_IPS = {
    "192.168.100.200",
    "10.0.0.99",
    "203.0.113.42",
    "198.51.100.7",
    "185.220.101.1",   # known Tor exit node
}

SEVERITY_MAP = {
    "BRUTE_FORCE":     "MEDIUM",
    "INVALID_USER":    "LOW",
    "PRIV_ESCALATION": "HIGH",
    "PORT_SCAN":       "HIGH",
    "ROOT_LOGIN":      "CRITICAL",
    "MALWARE_DROPPER": "CRITICAL",
    "ACCEPTED_PUBKEY": "HIGH",
    "KNOWN_BAD_IP":    "CRITICAL",
}

# Terminal colour codes
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[33m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
}


# -- Core analysis function ---------------------------------------------------
def analyze_log(log_path: str, brute_threshold: int = 5) -> dict:
    """Read a log file and return a dict with all detected alerts."""
    alerts = []
    failed_login_count = defaultdict(int)
    compiled = {k: re.compile(v, re.IGNORECASE) for k, v in PATTERNS.items()}

    with open(log_path, "r", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):

            # -- Pattern matching ---------------------------------------------
            for threat, regex in compiled.items():
                match = regex.search(line)
                if not match:
                    continue

                ip = match.group(1) if match.lastindex and match.lastindex >= 1 else "N/A"

                if threat == "BRUTE_FORCE":
                    failed_login_count[ip] += 1
                    if failed_login_count[ip] < brute_threshold:
                        continue
                    if failed_login_count[ip] > brute_threshold:
                        continue

                alerts.append({
                    "line":     lineno,
                    "threat":   threat,
                    "severity": SEVERITY_MAP[threat],
                    "ip":       ip,
                    "raw":      line.strip()[:150],
                    "ts":       datetime.now(timezone.utc).isoformat(),
                })

            # -- Bad-IP cross-reference ---------------------------------------
            for bad_ip in KNOWN_BAD_IPS:
                if bad_ip in line:
                    alerts.append({
                        "line":     lineno,
                        "threat":   "KNOWN_BAD_IP",
                        "severity": "CRITICAL",
                        "ip":       bad_ip,
                        "raw":      line.strip()[:150],
                        "ts":       datetime.now(timezone.utc).isoformat(),
                    })
                    break

    return {
        "log_file":     log_path,
        "analyzed_at":  datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "brute_counts": dict(failed_login_count),
        "alerts":       alerts,
    }


# -- Report printer -----------------------------------------------------------
def print_report(result: dict, output_path: str = "breach_report.json"):
    R = COLORS["RESET"]

    print("\n" + "=" * 60)
    print("      BREACH DETECTION REPORT")
    print("=" * 60)
    print(f"Log file    : {result['log_file']}")
    print(f"Analyzed at : {result['analyzed_at']}")
    print(f"Total alerts: {result['total_alerts']}")
    print("=" * 60 + "\n")

    if not result["alerts"]:
        print(f"{COLORS['LOW']}[OK] No suspicious activity detected.{R}\n")
        return

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        subset = [a for a in result["alerts"] if a["severity"] == severity]
        if not subset:
            continue
        c = COLORS[severity]
        print(f"{c}-- {severity} ({len(subset)} event(s)) --------------------{R}")
        for a in subset:
            print(f"{c}  [{a['severity']}] Line {a['line']:>5} | {a['threat']:<20} | IP: {a['ip']}{R}")
            print(f"           > {a['raw'][:100]}")
        print()

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Full JSON report saved -> {output_path}\n")


# -- Entry point --------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Scan system log files for breach indicators"
    )
    parser.add_argument("--log",       required=True, help="Path to log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed-login count before brute-force alert (default: 5)")
    parser.add_argument("--output",    default="breach_report.json",
                        help="Output JSON report path")
    args = parser.parse_args()

    if not Path(args.log).exists():
        print(f"[!] File not found: {args.log}")
        sys.exit(1)

    result = analyze_log(args.log, brute_threshold=args.threshold)
    print_report(result, output_path=args.output)


if __name__ == "__main__":
    main()
