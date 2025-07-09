# Threat Hunting Guide

## Overview

Threat hunting is the **proactive search** for threats that evade traditional security tools. It involves forming hypotheses, analyzing data, and identifying indicators of compromise (IOCs) using threat intelligence and behavioral analytics.

---

## Threat Hunting Process

### 1. Preparation
- Define scope and objectives
- Gather threat intelligence (e.g., MITRE ATT&CK, threat feeds)
- Understand your network baseline
- Determine expected and unexpected **parent-child process** relationships in your environment (e.g., what processes typically launch PowerShell, Wscript, etc.)

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
Apache logging library vulnerable to **remote code execution** (CVE-2021-44228). Known as **Log4Shell**, widely exploited in 2021.

### TTP (Tactics, Techniques, Procedures)
Used by attackers to describe how they operate. Tracked by the [MITRE ATT&CK Framework](https://attack.mitre.org/).

### SMB (Server Message Block)
Protocol used for Windows file sharing. Can be abused for **lateral movement** (e.g., EternalBlue → WannaCry).

### Parent-Child Process Relationships
Understanding parent-child process relationships is essential for identifying process anomalies. A parent process is one that spawns or launches another (child) process. An attacker may use trusted processes like `winword.exe` or `explorer.exe` to spawn malicious children such as `powershell.exe`, `cmd.exe`, or `rundll32.exe`. By establishing a baseline for normal process behavior, analysts can more effectively detect threats using process lineage.

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

## Parent-Child Process Analysis

### What is a Parent Process?
A **parent process** is the process that spawns (or launches) another process, known as a **child process**.

Example:
explorer.exe → powershell.exe → rundll32.exe

pgsql
Copy
Edit

This lineage helps identify abnormal or malicious behavior.

###  Why It Matters
Attackers frequently abuse trusted processes to spawn malicious children. Hunting for unusual chains can reveal fileless malware, LOLBins, or lateral movement.

###  Suspicious Examples

| Parent           | Child               | Why It's Suspicious                         |
|------------------|---------------------|----------------------------------------------|
| winword.exe      | powershell.exe      | Office shouldn't launch PowerShell          |
| explorer.exe     | cmd.exe             | Unusual without direct user interaction     |
| svchost.exe      | cmd.exe             | Rare and risky                              |
| powershell.exe   | rundll32.exe        | Seen in malware staging                     |
| outlook.exe      | wscript.exe         | Scripted malware via phishing               |

### Hunting With Sysmon (Event ID 1)

Example query (Elastic or Wazuh):
```bash
process.name: "powershell.exe" AND NOT parent_process.name: ("explorer.exe", "cmd.exe")
This hunts for powershell.exe processes started by uncommon or suspicious parents.

Hunting Questions
Is PowerShell being launched by Office applications?

Are scripting engines started by browsers or email clients?

Is a background service spawning shells or network tools?

MITRE ATT&CK Techniques
Technique	ID	Description
Command Execution	T1059	PowerShell, CMD, etc.
Process Injection	T1055	Injecting code into legit processes
Masquerading	T1036	Disguising as trusted processes

Last updated: July 2025
Maintained by Cyrus Lomibao
