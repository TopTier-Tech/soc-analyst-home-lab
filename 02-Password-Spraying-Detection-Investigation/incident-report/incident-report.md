# Incident Report – Password Spraying Attack

**Incident ID:** PS-2026-0831  
**Date of Incident:** 31 August 2026  
**Reported By:** Nmesoma Kingsley (Lab Environment)  
**Severity:** Medium  
**Status:** Contained / Investigated  

---

## 1. Executive Summary

A password spraying attack was detected against the CORP Active Directory domain. The attacker (IP `192.168.56.103`, hostname `KALI`) attempted authentication against multiple user accounts using a single common password via SMB (NTLM). No account lockouts occurred, confirming a classic low-and-slow password spraying technique. One successful authentication was later observed for account `soc_test3`.

---

## 2. Timeline of Events

| Time (approx.)       | Event Description                                      | Evidence |
|----------------------|--------------------------------------------------------|----------|
| ~05:24               | Reconnaissance – Ping & Nmap scan of DC (192.168.56.10)| 01 & 02  |
| 11:05 – 11:06        | Multiple failed logon attempts (Event 4625)            | 03–06    |
| 11:05 – 11:08        | 6–7 unique accounts targeted from single source IP     | 07       |
| 11:08                | Successful authentication observed for `soc_test3`     | 08       |
| Throughout           | Zero Account Lockout events (Event 4740)               | 09       |

---

## 3. Technical Details

### Attacker Information
- **Source IP:** 192.168.56.103
- **Workstation Name:** KALI
- **Authentication Protocol:** NTLM
- **Logon Type:** 3 (Network)

### Targeted Accounts
- `soc_test`
- `soc_test1`
- `soc_test2`
- `soc_test3`
- `soc_test4`
- `soc_test5`
- (plus blank/NULL SID entries)

### Key Windows Events
- **Event ID 4625** – Failed logons (Status `0xC000006D`, Sub Status `0xC000006A` – bad password)
- **Event ID 4624** – One successful logon for `soc_test3`
- **Event ID 4740** – No lockouts generated

### Splunk Findings
- 6 failed authentication events in a short window
- 7 unique accounts targeted from a single source
- Clear password spraying pattern confirmed by high unique-account count with low attempts per account

---

## 4. Root Cause

The attack succeeded in generating failed logons because:
1. Multiple accounts were targeted with the same password (spraying).
2. Account lockout threshold was either disabled or set high enough that the low volume per account did not trigger lockouts.
3. NTLM authentication was allowed over the network.

---

## 5. Impact Assessment

- **Confidentiality:** Low (no clear evidence of data access at time of report)
- **Integrity:** None observed
- **Availability:** None (no lockouts)
- **Business Impact:** Potential credential compromise of `soc_test3`

---

## 6. Containment & Remediation Actions

1. Confirmed source IP `192.168.56.103` as the sole attacker.
2. Reviewed successful authentication of `soc_test3` and recommended password reset.
3. Verified no additional lateral movement or privileged activity in the immediate timeframe.
4. Recommended enabling stricter account lockout policy and monitoring for high unique-account authentication failures.

---

## 7. Recommendations

- Implement detection rule: Alert when `unique_accounts >= 5` from a single source IP within a short time window (see SPL query #6).
- Enforce MFA for all accounts, especially those with elevated privileges.
- Restrict NTLM where possible and prefer Kerberos.
- Continuously tune the Password Spraying Detection dashboard.
- Forward all Domain Controller Security logs to Splunk in real time.

---

## 8. Evidence Collected

All evidence is stored in the `screenshots/` folder of this repository and correlated in Splunk.

**Dashboard used for investigation:**  
`10-password-spraying-dashboard.png`

---

**Report prepared by:** Nmesoma Kingsley 
**Date of Report:** 01 September 2026  
**Classification:** Internal Lab Use
