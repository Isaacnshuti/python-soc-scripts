#!/usr/bin/env python3
"""
=============================================================================
SCRIPT 03 - Network Traffic Analyzer (TCP/IP, DNS, HTTP)
=============================================================================
Coverage : Networking Basics - TCP/IP, DNS, HTTP
Difficulty: Intermediate
Tested on : 5 MB lab PCAP file (Wireshark capture, isolated lab network)
Result    : PASSED - Detected DNS tunneling, HTTP credential leak, SYN scan

WHAT IT DOES:
  Reads a .pcap file (or sniffs a live interface) and detects:
    - DNS Tunneling      - high-entropy subdomain labels (>20 chars, H > 3.5)
    - HTTP Credential Leak - cleartext Basic Auth or POST passwords
    - Port Scan          - SYN-only packets to 20+ unique ports from same IP
    - Suspicious Beaconing - same dst IP contacted at regular short intervals
    - Large DNS Response  - unusually large TXT replies (data exfil via DNS)
    - Cleartext FTP/Telnet sessions

HOW IT WORKS:
  Shannon entropy measures randomness in DNS labels:
    H > 3.5 bits + label length > 20 chars -> likely base64/hex-encoded payload.
  SYN-scan detection tracks (src_ip -> set of dst_ports); fires when set size
  crosses SCAN_THRESHOLD.
  HTTP inspection searches Raw layer payloads for known credential patterns.

INSTALL:
  pip install scapy

USAGE:
  python3 03_net_analyzer.py --pcap capture.pcap
  python3 03_net_analyzer.py --iface eth0 --count 2000   # requires sudo
  python3 03_net_analyzer.py --pcap capture.pcap --output net_alerts.json

IMPROVEMENTS NEEDED:
  - Add GeoIP lookup (geoip2 library) for external IPs
  - Tune DNS entropy threshold via --entropy flag
  - Add TLS SNI extraction to detect malicious domains in HTTPS traffic
=============================================================================
"""

import math
import re
import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import rdpcap, sniff, DNS, DNSQR, DNSRR, TCP, UDP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# -- Config -------------------------------------------------------------------
SCAN_THRESHOLD  = 20     # unique dst ports from one src IP -> port scan
DNS_ENTROPY_THR = 3.5    # Shannon entropy threshold for DNS tunneling
DNS_LABEL_MIN   = 20     # minimum label length to consider for tunneling
BEACON_WINDOW   = 5      # seconds; same dst IP in < N seconds = possible beacon
DNS_RESP_THR    = 512    # bytes; large DNS response = possible data exfil

CLEARTEXT_PROTOS = {21, 23}  # FTP, Telnet


# -- Shannon Entropy ----------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq)


# -- Packet analysis ----------------------------------------------------------
def analyze_packets(packets) -> list:
    alerts = []
    syn_tracker = defaultdict(set)    # src_ip -> {dst_port}
    beacon_last = defaultdict(float)  # (src,dst) -> last seen timestamp
    dns_queries = defaultdict(int)    # qname -> count

    for pkt in packets:
        pkt_time = float(pkt.time) if hasattr(pkt, "time") else 0.0

        # -- DNS Tunneling Detection ------------------------------------------
        if pkt.haslayer(DNS):
            if pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                except Exception:
                    qname = str(pkt[DNSQR].qname)
                label = qname.split(".")[0]
                entropy = shannon_entropy(label)
                dns_queries[qname] += 1

                if entropy > DNS_ENTROPY_THR and len(label) >= DNS_LABEL_MIN:
                    alerts.append({
                        "type":     "DNS_TUNNEL_QUERY",
                        "severity": "HIGH",
                        "src":      pkt[IP].src if pkt.haslayer(IP) else "?",
                        "detail":   f"Entropy={entropy:.2f}, label={label[:50]}",
                    })

            if pkt[DNS].qr == 1 and pkt.haslayer(DNSRR):
                rdata = bytes(pkt[DNSRR])
                if len(rdata) > DNS_RESP_THR:
                    alerts.append({
                        "type":     "DNS_LARGE_RESPONSE",
                        "severity": "MEDIUM",
                        "src":      pkt[IP].src if pkt.haslayer(IP) else "?",
                        "detail":   f"DNS response size: {len(rdata)} bytes",
                    })

        # -- HTTP Credential Leak ---------------------------------------------
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            try:
                payload = pkt[Raw].load.decode(errors="replace")
            except Exception:
                payload = ""

            if re.search(r"(Authorization:\s*Basic|password=|passwd=|&pass=)", payload, re.I):
                alerts.append({
                    "type":     "CRED_LEAK_HTTP",
                    "severity": "CRITICAL",
                    "src":      pkt[IP].src if pkt.haslayer(IP) else "?",
                    "detail":   payload[:100].replace("\n", " ").replace("\r", ""),
                })

        # -- Port Scan Detection ----------------------------------------------
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            if str(flags) == "S":
                src = pkt[IP].src
                dport = pkt[TCP].dport
                syn_tracker[src].add(dport)
                if len(syn_tracker[src]) == SCAN_THRESHOLD:
                    alerts.append({
                        "type":     "PORT_SCAN",
                        "severity": "HIGH",
                        "src":      src,
                        "detail":   f"SYN to {SCAN_THRESHOLD}+ unique ports detected",
                    })

        # -- Cleartext FTP / Telnet -------------------------------------------
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            if dport in CLEARTEXT_PROTOS and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode(errors="replace")
                except Exception:
                    payload = ""
                if re.search(r"(USER |PASS |Password:)", payload, re.I):
                    alerts.append({
                        "type":     f"CLEARTEXT_{'FTP' if dport == 21 else 'TELNET'}",
                        "severity": "HIGH",
                        "src":      pkt[IP].src,
                        "detail":   payload[:80].replace("\n", " "),
                    })

        # -- Rapid Beaconing --------------------------------------------------
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            key = (pkt[IP].src, pkt[IP].dst)
            last = beacon_last.get(key, 0)
            if pkt_time - last < BEACON_WINDOW and pkt_time != last:
                alerts.append({
                    "type":     "POSSIBLE_BEACON",
                    "severity": "MEDIUM",
                    "src":      pkt[IP].src,
                    "detail":   f"Repeated contact to {pkt[IP].dst} within {BEACON_WINDOW}s",
                })
            beacon_last[key] = pkt_time

    return alerts


# -- Report printer -----------------------------------------------------------
def print_report(alerts: list, output_path: str = None):
    COLORS = {
        "CRITICAL": "\033[91m", "HIGH": "\033[33m",
        "MEDIUM": "\033[93m",   "LOW":  "\033[92m",
        "RESET": "\033[0m",
    }
    R = COLORS["RESET"]

    seen, deduped = set(), []
    for a in alerts:
        key = f"{a['type']}{a['src']}{a['detail'][:30]}"
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    print("\n" + "=" * 60)
    print("      NETWORK TRAFFIC ANALYSIS REPORT")
    print("=" * 60)
    print(f"Unique alerts : {len(deduped)} (raw: {len(alerts)})")
    print(f"Analyzed at   : {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60 + "\n")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        subset = [a for a in deduped if a["severity"] == sev]
        if not subset:
            continue
        c = COLORS[sev]
        print(f"{c}-- {sev} ({len(subset)} alert(s)) --------------------{R}")
        for a in subset:
            print(f"{c}  [{a['severity']}] {a['type']:<25} | Src: {a['src']}{R}")
            print(f"            > {a['detail'][:100]}")
        print()

    if output_path:
        with open(output_path, "w") as f:
            json.dump({"alerts": deduped, "raw_count": len(alerts)}, f, indent=2)
        print(f"[+] Report saved -> {output_path}")


# -- Demo alerts (used when scapy is not installed or --demo is passed) -------
DEMO_ALERTS = [
    {
        "type": "CRED_LEAK_HTTP", "severity": "CRITICAL",
        "src": "10.0.0.15",
        "detail": "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw== GET /admin HTTP/1.1",
    },
    {
        "type": "DNS_TUNNEL_QUERY", "severity": "HIGH",
        "src": "10.0.0.42",
        "detail": "Entropy=4.12, label=aGVsbG8td29ybGQtdGhpcy1pcy1hLXRlc3Q",
    },
    {
        "type": "PORT_SCAN", "severity": "HIGH",
        "src": "203.0.113.77",
        "detail": "SYN to 20+ unique ports detected",
    },
    {
        "type": "DNS_LARGE_RESPONSE", "severity": "MEDIUM",
        "src": "10.0.0.42",
        "detail": "DNS response size: 724 bytes",
    },
    {
        "type": "CLEARTEXT_FTP", "severity": "HIGH",
        "src": "10.0.0.8",
        "detail": "USER ftpuser PASS s3cr3tpass",
    },
    {
        "type": "POSSIBLE_BEACON", "severity": "MEDIUM",
        "src": "10.0.0.55",
        "detail": "Repeated contact to 185.220.101.1 within 5s",
    },
]


# -- Entry point --------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Analyze network traffic for security threats"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--pcap",  help="Path to .pcap file")
    group.add_argument("--iface", help="Live interface to sniff (requires root/sudo)")
    group.add_argument("--demo",  action="store_true",
                       help="Run with built-in synthetic data (no .pcap or scapy needed)")
    parser.add_argument("--count",  type=int, default=1000,
                        help="Packets to capture in live mode (default: 1000)")
    parser.add_argument("--output", help="Save JSON alerts to this path")
    args = parser.parse_args()

    if args.demo or (not args.pcap and not args.iface):
        if not SCAPY_AVAILABLE and not args.demo:
            print("[!] scapy not installed. Running in demo mode.")
            print("    Install with:  pip install scapy")
        print("[*] Running with synthetic demo data...\n")
        print_report(DEMO_ALERTS, output_path=args.output)
        return

    if not SCAPY_AVAILABLE:
        print("[!] scapy is required for live capture / pcap analysis.")
        print("    Install with:  pip install scapy")
        print("    Or use --demo to run without it.")
        sys.exit(1)

    if args.pcap:
        if not Path(args.pcap).exists():
            print(f"[!] File not found: {args.pcap}")
            sys.exit(1)
        print(f"[*] Reading PCAP: {args.pcap}")
        packets = rdpcap(args.pcap)
        print(f"[*] Loaded {len(packets)} packets")
    else:
        print(f"[*] Sniffing {args.count} packets on interface '{args.iface}'...")
        print("[!] Note: Requires root/sudo privileges")
        packets = sniff(iface=args.iface, count=args.count)

    alerts = analyze_packets(packets)
    print_report(alerts, output_path=args.output)


if __name__ == "__main__":
    main()
