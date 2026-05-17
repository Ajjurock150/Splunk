# 🔴 Splunk SIEM Home Lab — Threat Detection & Log Analysis

![Splunk](https://img.shields.io/badge/SIEM-Splunk-black?style=flat-square&logo=splunk)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)
![Dataset](https://img.shields.io/badge/Dataset-BOTSv3-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed-green?style=flat-square)

---

## 📌 Project Overview

This project simulates a real-world SOC environment by deploying **Splunk Enterprise** with a **Universal Forwarder** on a Windows machine, ingesting the **BOTSv3 (Boss of the SOC v3)** dataset — a 2M+ event CTF-style dataset used by Splunk for threat hunting training.

The goal: act as a Tier 1 SOC Analyst detecting brute-force attacks, privilege escalation, lateral movement, and anomalous process creation from raw logs.

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|------|---------|
| Splunk Enterprise | SIEM platform — indexing, searching, alerting |
| Splunk Universal Forwarder | Log collection agent on Windows endpoints |
| BOTSv3 Dataset | Simulated enterprise attack log data (~2M events) |
| SPL (Search Processing Language) | Query language for log analysis |
| Windows Event Viewer | Manual log inspection and baseline comparison |

---

## ⚙️ Environment Setup

```
Host OS       : Windows 11
Splunk Version: Splunk Enterprise (Free Trial / Dev License)
Dataset       : BOTSv3 (downloaded from Splunk's GitHub)
Forwarder     : Splunk Universal Forwarder → local Splunk instance
Index Name    : botsv3
```

### Installation Steps
1. Installed Splunk Enterprise on Windows, configured on port `8000`
2. Downloaded and extracted BOTSv3 dataset into Splunk's `apps` directory
3. Deployed Universal Forwarder configured to monitor Windows Event Logs
4. Created a custom index `botsv3` and verified data ingestion via `index=botsv3 | head 10`

---

## 🎯 Attack Story — What Happened?

The BOTSv3 dataset simulates a targeted attack against a fictional company. As a SOC analyst I investigated the following attack chain:

```
Attacker Recon → Credential Brute Force → Successful Login 
    → Lateral Movement → Privilege Escalation → Data Exfiltration
```

**Key findings during investigation:**
- Multiple failed logins (Event ID 4625) from a single source IP against several accounts
- A successful login (Event ID 4624) immediately after the failure spike — classic brute-force success
- A new process was spawned under the compromised account (Event ID 4688) — `cmd.exe` → `powershell.exe`
- Privilege escalation attempt detected via special privileges assigned (Event ID 4672)
- Outbound connection to a suspicious external IP discovered in network logs

---

## 🔍 Detection Logic — SPL Queries

### 1. Brute-Force Detection (Failed Login Spike)
```spl
index=botsv3 EventCode=4625
| stats count by src_ip, user, _time
| where count > 5
| sort - count
```

### 2. Successful Login After Failures (Brute-Force Success Indicator)
```spl
index=botsv3 (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes by src_ip, user
| where failures > 5 AND successes > 0
| sort - failures
```

### 3. Privilege Escalation Detection
```spl
index=botsv3 EventCode=4672
| stats count by Account_Name, Privilege_List, _time
| sort - _time
```

### 4. Suspicious Process Creation (Living off the Land)
```spl
index=botsv3 EventCode=4688
| eval suspicious=if(match(New_Process_Name, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)"), "YES", "NO")
| where suspicious="YES"
| table _time, Account_Name, New_Process_Name, Creator_Process_Name, ComputerName
| sort - _time
```

### 5. Lateral Movement Detection (Logon Type 3 — Network)
```spl
index=botsv3 EventCode=4624 Logon_Type=3
| stats count by src_ip, user, ComputerName
| where count > 3
| sort - count
```

### 6. Timechart — Login Failure Spike Over Time
```spl
index=botsv3 EventCode=4625
| timechart span=1h count by src_ip
```

---

## 📊 Dashboard & Alerts Created

| Dashboard Panel | Description |
|-----------------|-------------|
| Failed Logins Over Time | Timechart of 4625 events per hour by source IP |
| Top Targeted Accounts | Bar chart of most-failed usernames |
| Privilege Escalation Events | Table of 4672 events with account and privilege info |
| Suspicious Process Launches | Real-time table of cmd/powershell spawns |
| Active Logon Sessions | Current logged-in accounts by machine |

**Alert Created:**
- Trigger: `EventCode=4625 count > 10 within 5 minutes from same src_ip`
- Action: Email notification + Splunk notable event

---

## 🧯 Remediation Recommendations

| Finding | Recommended Action |
|---------|-------------------|
| Brute-force from external IP | Block IP at perimeter firewall; enable account lockout policy (5 attempts) |
| Successful login post-failure | Force password reset for compromised account; enable MFA |
| Powershell spawned from cmd | Enable PowerShell Script Block Logging; restrict execution policy |
| Privilege escalation | Audit privileged group memberships; apply principle of least privilege |
| Lateral movement (Logon Type 3) | Segment network; disable NTLM where possible; enforce SMB signing |

---

## 📚 Key Event IDs Reference

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon attempt |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned to new logon |
| 4688 | New process created |
| 4768 | Kerberos TGT requested |
| 4776 | NTLM authentication attempt |

---

## 🔗 References
- [Splunk BOTSv3 Dataset](https://github.com/splunk/botsv3)
- [MITRE ATT&CK — Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [Windows Security Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
