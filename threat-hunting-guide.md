# Threat Hunting Guide

## Overview

Threat hunting is the **proactive search** for threats that evade 
traditional security tools. It involves forming hypotheses, analyzing 
data, and identifying indicators of compromise (IOCs) using threat 
intelligence and behavioral analytics.

---

## Threat Hunting Process

### 1. Preparation
- Define scope and objectives
- Gather threat intelligence (e.g., MITRE ATT&CK, threat feeds)
- Understand your network baseline

### 2. Create a Hypothesis
- Example: "Attackers may use SMB for lateral movement during off-hours"
- Use known TTPs or anomalies as a base

### 3. Data Collection
- Gather data from:
  - Endpoints (EDR, Sysmon, Wazuh agents)
  - SIEM (Wazuh, Splunk, Elastic)
  - Network logs (Suricata, Zeek)
  - Cloud services (Azure/AWS logs)

### 4. Data Analysis
- Search for suspicious processes or abnormal login behavior
- Map to MITRE ATT&CK TTPs
- Use queries/scripts to hunt in SIEM or EDR tools

### 5. Detection and Validation
- Confirm malicious activity
- Capture IOCs (file hashes, IPs, domains)
- Investigate for false positives

### 6. Response
- Contain threats
- Trigger IR procedures
- Document findings

### 7. Lessons Learned
- Update SIEM rules
- Refine detection techniques
- Share findings with your team

---

## Key Concepts

### Log4j
Apache logging library vulnerable to **remote code execution** 
(CVE-2021-44228). Known as **Log4Shell**, widely exploited in 2021.

### TTP (Tactics, Techniques, Procedures)
Used by attackers to describe how they operate. Tracked by the [MITRE 
ATT&CK Framework](https://attack.mitre.org/).

### SMB (Server Message Block)
Protocol used for Windows file sharing. Can be abused for **lateral 
movement** (e.g., EternalBlue → WannaCry).

---

## Common Tools

| Type         | Tools                             |
|--------------|-----------------------------------|
| SIEM         | Wazuh, Splunk, Elastic Stack       |
| EDR          | Sysmon, CrowdStrike, SentinelOne   |
| Network      | Zeek, Suricata, Wireshark          |
| Threat Intel | VirusTotal, MISP, AbuseIPDB        |
| Scripting    | PowerShell, Python, Bash           |

---

## MITRE ATT&CK Examples

| Tactic              | Technique               | Tool |
|---------------------|--------------------------|------|
| Execution           | T1059 – Command Scripting | PowerShell |
| Lateral Movement    | T1021.002 – SMB/Windows Admin Shares | PsExec |
| Credential Access   | T1003 – Credential Dumping | Mimikatz |

---

> Last updated: July 2025  
> Maintained by [Cyrus Lomibao](https://github.com/yourusername)

