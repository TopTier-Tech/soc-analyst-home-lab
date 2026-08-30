# Incident Report – Brute Force Detection Lab

**Date:** 28 August 2026  
**Analyst:** Nmesoma Kingsly  
**Severity:** High  
**MITRE ATT&CK:** T1110 – Brute Force  

---

## 1. Summary

A brute-force attack was simulated from a Kali Linux machine against a Windows Server 2025 domain controller (DC01.corp.local). Multiple failed SMB authentication attempts were made against the account `soc_test`. The activity was successfully detected in both Windows Event Viewer and Splunk.

---

## 2. Lab Environment

| Role              | System                  | IP Address       |
|-------------------|-------------------------|------------------|
| Attacker          | Kali Linux              | 192.168.56.103   |
| Target            | Windows Server 2025 (DC01.corp.local) | 192.168.56.10 |
| SIEM              | Splunk Enterprise       | -                |
| Targeted Account  | soc_test (CORP domain)  | -                |

---

## 3. Attack Timeline

| Time (approx)       | Activity                                      | Evidence                     |
|---------------------|-----------------------------------------------|------------------------------|
| 28 Aug 2026         | Connectivity test (ping)                      | Kali screenshot              |
| 28 Aug 2026 13:31   | Port scan (nmap -p 445)                       | Port 445 open                |
| 28 Aug 2026 10:54am | Multiple SMB brute-force attempts             | smbclient failures           |
| 28 Aug 2026         | Failed logons recorded (Event ID 4625)        | Windows Event Viewer         |
| 28 Aug 2026         | Failed logons visible in Splunk               | Splunk search                |
| 28 Aug 2026 1:05pm  | One successful logon observed (Event ID 4624) | Splunk (soc_test)            |

---

## 4. Key Findings

- **Attack Source:** 192.168.56.103 (Kali Linux)
- **Target Host:** DC01.corp.local (192.168.56.10)
- **Targeted Account:** soc_test
- **Logon Type:** 3 (Network)
- **Failure Reason:** Unknown user name or bad password
- **Number of failed attempts:** Multiple (visible in both Event Viewer and Splunk)
- **Successful login:** 1 successful EventCode 4624 for account soc_test was observed

---

## 5. Detection Evidence

### Windows Event Viewer
- Event ID **4625** – An account failed to log on
- Source Network Address: **192.168.56.103**
- Workstation Name: **KALI**
- Account Name: **soc_test**

### Splunk
- Search used for failed logins:  
  `index=* host=DC01 EventCode=4625`
- Search used for successful login:  
  `index=* EventCode=4624 host="DC01" soc_test`

---

## 6. MITRE ATT&CK Mapping

- **Tactic:** Credential Access  
- **Technique:** T1110 – Brute Force  
- **Sub-technique:** T1110.001 – Password Guessing (via SMB)

---

## 7. Recommendations

1. Implement account lockout policies after a defined number of failed attempts.
2. Monitor Event ID 4625 in real time with Splunk alerts.
3. Restrict SMB access (port 445) from untrusted networks.
4. Use strong, unique passwords for all domain accounts.
5. Consider enabling MFA for privileged and service accounts.

---

## 8. Conclusion

The brute-force activity originating from Kali Linux was successfully simulated, logged on the Windows Server, and detected in Splunk. This lab demonstrates end-to-end detection of a common credential access technique (T1110).
