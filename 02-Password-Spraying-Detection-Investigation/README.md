
# Password Spraying Detection & Investigation

[Dashboard Hero] screenshots/10-password-spraying-dashboard.png

## Project Overview

This repository documents a complete **Password Spraying** attack simulation and detection lab performed against a Windows Active Directory environment.

The goal was to:
1. Simulate a realistic low-and-slow password spraying attack from Kali Linux
2. Capture the attack in Windows Security Event Logs
3. Detect and investigate the attack using Splunk
4. Build a dedicated detection dashboard
5. Produce a formal incident report

---

## Lab Environment

| Role              | Details                          |
|-------------------|----------------------------------|
| Attacker          | Kali Linux – `192.168.56.103`   |
| Target            | Windows Server 2025 DC – `DC01.corp.local` (`192.168.56.10`) |
| Domain            | `CORP`                           |
| Protocol          | SMB / NTLM                       |
| SIEM              | Splunk Enterprise                |




---

## Attack Summary

1. Reconnaissance (Ping + Nmap) against the Domain Controller
2. Password spraying using `smbclient` against multiple `soc_test*` accounts
3. All attempts initially failed with `NT_STATUS_LOGON_FAILURE`
4. Windows Event ID **4625** generated for each failed attempt
5. One successful authentication later observed (Event ID **4624**)
6. Zero account lockouts (Event ID **4740**)

---

## Detection Highlights

- Single source IP targeting **7 unique accounts**
- Low volume per account (classic spraying behaviour)
- NTLM authentication + Logon Type 3
- Clear visibility in both Event Viewer and Splunk
- Custom dashboard built for ongoing monitoring

---

## How to Use This Repository

1. Review the screenshots in chronological order
2. Examine the SPL queries in `spl-queries/password-spraying-detection.spl`
3. Read the full incident report in `incident-report/incident-report.md`
4. Recreate the dashboard using the provided queries

---

## Key SPL Queries

The most important detection query:

```spl
index=* EventCode=4625 
| stats count as failed_attempts  
        dc(Account_Name) as unique_accounts  
        values(Account_Name) as targeted_accounts  
        by Source_Network_Address 
| where unique_accounts >= 5 
| sort -unique_accounts 
 
Full set of queries is available in the spl-queries/ folder. 
 
---

## Lessons Learned 
 
High unique-account count from a single IP is a strong indicator of password spraying 
Account lockout policies alone are not enough — volume and uniqueness matter 
Real-time log forwarding to a SIEM + purpose-built dashboards significantly improve detection speed 
Even “failed” spraying attempts provide rich forensic evidence 
 
---

## Author 
 
Nmesoma Kingsley / Blue Team Lab Project 
 
Date: August – September 2026 
