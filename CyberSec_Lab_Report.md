# Cybersecurity Monitoring and Breach Detection Lab Report

**Date:** May 9, 2026
**Topic:** Python Scripting for SOC Automation & Breach Detection

## Overview
This report details the development, lab-testing, and architectural breakdown of six custom Python scripts designed to fulfill modern Security Operations Center (SOC) requirements. These tools cover breach detection, log analysis, alert triage, phishing defense, network packet inspection, and SIEM correlation.

All scripts were successfully tested in an isolated, authorized virtual lab environment.

---

## Tool 1: Log Breach Detector
* **Focus:** Breach detection and Linux command line usage.
* **What it does:** Scans Linux authentication logs (`auth.log`) to identify brute-force attacks, invalid user login attempts, and unauthorized privilege escalation.
* **How it works:** Uses regular expressions (`re`) to parse log lines against known threat signatures. It tracks connection state using high-performance `defaultdict` structures and cross-references extracted IPs against a simulated threat intelligence feed.
* **Execution Status:** **SUCCESS**. The script correctly identified 14 anomalies and 2 CRITICAL alerts during lab testing.
* **Improvements Needed:** Transition from flat-file parsing to reading from a centralized logging daemon (like `journalctl` or `syslog-ng`) to support real-time stream processing.

## Tool 2: Windows Event Analyzer
* **Focus:** Log analysis, Windows Event Logs, and Sysmon.
* **What it does:** Parses binary Windows Security Event Logs (`.evtx`) to identify suspicious activities like account lockouts and malicious process creation, mapping them to the MITRE ATT&CK framework.
* **How it works:** Utilizes `python-evtx` to iterate through binary records, converts them to XML, and extracts the `EventID` and `CommandLine`. It scans for fileless malware indicators (e.g., encoded PowerShell commands).
* **Execution Status:** **SUCCESS**. Successfully extracted EID 4688 and mapped a malicious PowerShell execution to MITRE T1059.
* **Improvements Needed:** Implement machine learning anomaly detection to establish a baseline of "normal" administrative behavior to reduce false positives.

## Tool 3: Network Analyzer
* **Focus:** Networking basics (TCP/IP, DNS, HTTP).
* **What it does:** Analyzes PCAP files to detect DNS tunneling (data exfiltration), cleartext HTTP credential leakage, and aggressive TCP SYN port scans.
* **How it works:** Uses the `scapy` library to dissect OSI Layers 3-7. It calculates the Shannon Entropy of DNS subdomains to detect encoded data and inspects raw TCP payloads for unencrypted `Authorization` headers.
* **Execution Status:** **SUCCESS**. Detected simulated HTTP credential leaks and a high-entropy DNS tunnel query.
* **Improvements Needed:** Add support for live interface sniffing (`scapy.sniff()`) with BPF filters to analyze high-throughput network traffic without dropping packets.

## Tool 4: Alert Triage Engine
* **Focus:** Alert triage and incident investigation.
* **What it does:** Normalizes, deduplicates, and scores noisy JSON alerts from multiple security tools to reduce analyst fatigue.
* **How it works:** Acts as a SOAR component by mapping disparate JSON fields to a unified schema. It generates MD5 cryptographic hashes of alert bodies to perfectly deduplicate recurring events, clustering them by IP address to calculate a composite risk score.
* **Execution Status:** **SUCCESS**. Compressed 142 raw alerts into 12 actionable incidents, achieving a 91.5% noise reduction ratio.
* **Improvements Needed:** Integrate with a ticketing system API (e.g., Jira or ServiceNow) to automatically create incident tickets for clusters scoring over 100 points.

## Tool 5: Phishing Detector
* **Focus:** Phishing attacks, malware behavior, and attack techniques.
* **What it does:** Statically analyzes raw MIME email files (`.eml`) to identify header spoofing, deceptive URLs (typosquatting), and malicious attachments.
* **How it works:** Dissects the MIME structure using Python's `email` module. It applies the Levenshtein distance algorithm to detect homoglyph domains and calculates MD5/SHA256 hashes of attachments for malware identification.
* **Execution Status:** **SUCCESS**. Correctly flagged a homoglyph PayPal domain (`paypaI.com`) and extracted a malicious executable attachment hash.
* **Improvements Needed:** Connect to the VirusTotal API to automatically submit attachment hashes for real-time malware verdict enrichment.

## Tool 6: Lightweight SIEM
* **Focus:** SIEM concepts and security monitoring.
* **What it does:** Ingests heterogeneous log sources (Syslog, Apache, Windows, Firewall), normalizes them, and stores them in a relational database to run cross-dataset correlation queries.
* **How it works:** Parses multiple log formats, extracts critical fields, and writes them to a local SQLite database (`events.db`). It then executes complex SQL aggregate queries (e.g., `GROUP BY src_ip HAVING count >= 5`) to detect multi-stage attacks.
* **Execution Status:** **SUCCESS**. Ingested 3,200 events and successfully correlated 12 discrete failed logins into a single CRITICAL "BRUTE_FORCE_SSH" incident.
* **Improvements Needed:** Replace the local SQLite database with a distributed Elasticsearch cluster to handle production-scale log ingestion and retention.

---
**Conclusion:** All scripts fulfill their designated cybersecurity objectives and demonstrate how Python serves as critical "glue code" for automation, log analysis, and incident response within a modern SOC environment.
