# Brute Force Attack Detection and Investigation Using Splunk

## Project Overview

This project demonstrates the detection and investigation of a controlled brute force attack against Windows Server 2025 using Splunk Enterprise as the SIEM. Kali Linux was used as the simulated attacker, while Windows Server 2025 served as the target. Windows Security Event Logs were collected through Splunk Universal Forwarder and analyzed using SPL.

## Objective

The objective was to simulate repeated authentication attempts, generate security telemetry, identify the attack through Windows Event Logs and Splunk, investigate the authentication timeline, determine whether successful authentication occurred, and create a reusable detection process.

## Lab Environment

| Role              | System                        | IP Address       |
|-------------------|-------------------------------|------------------|
| Attacker          | Kali Linux                    | 192.168.56.103   |
| Target            | Windows Server 2025 (DC01)    | 192.168.56.10    |
| Domain            | CORP                          | -                |
| Targeted Account  | soc_test                      | -                |
| SIEM              | Splunk Enterprise             | -                |

## Network Architecture

See the architecture diagram in the `architecture` folder (`soc-lab-architecture.png`).

**High-level view:**

- Kali Linux (Attacker) → Windows Server 2025 (Target)
- Windows Server 2025 → Splunk Universal Forwarder → Splunk Enterprise

## Attack Simulation

A brute-force attack was performed from Kali Linux against the Windows Server using the SMB protocol (port 445).

## Reconnaissance

- Connectivity was confirmed with `ping 192.168.56.10`
- Port scanning was performed with:  
  `nmap -p 445 192.168.56.10`  
  Result: Port 445/tcp open (microsoft-ds)

## Authentication Attack

Multiple failed authentication attempts were made using:

```bash
smbclient -L //192.168.56.10 -U 'CORP\soc_test'


`NT_STATUS_LOGON_FAILURE`

## Windows Event Investigation

Windows Event Viewer showed multiple **Event ID 4625 (Failed Logon)** entries.

**Event Details:**

* **Account Name:** `soc_test`
* **Account Domain:** `CORP`
* **Source Network Address:** `192.168.56.103`
* **Workstation Name:** `KALI`
* **Logon Type:** `3 (Network)`
* **Failure Reason:** `Unknown user name or bad password`

These events confirmed that multiple failed network authentication attempts were being generated against the `soc_test` account from the Kali Linux machine.

## Splunk Investigation

The failed authentication events were successfully ingested into Splunk.

### Main Search

```spl
index=* host=DC01 EventCode=4625
```

Successful authentication events were also investigated using:

```spl
index=* EventCode=4624 host="DC01" soc_test
```

One successful logon **EventCode 4624** for the `soc_test` account was observed and investigated to determine whether the simulated brute force activity resulted in a successful authentication.

## Detection Logic

The detection focuses on identifying multiple failed authentication attempts originating from the same source IP and targeting the same account within a short period.

This pattern can indicate password guessing or brute force activity.

## SPL Queries

### Brute Force Detection Query

```spl
index=* host=DC01 EventCode=4625
| stats count as FailedAttempts by Source_Network_Address, Account_Name
| where FailedAttempts >= 5
| sort - FailedAttempts
```

### Successful Login Investigation Query

```spl
index=* EventCode=4624 host="DC01" soc_test
```

## Successful Authentication Investigation

One successful authentication event, **EventCode 4624**, was found for the `soc_test` account on `DC01`.

The event was investigated to determine whether the brute force activity resulted in a successful compromise.

The presence of both failed authentication events (**4625**) and a subsequent successful authentication event (**4624**) demonstrates why SOC analysts should correlate failed and successful authentication activity during an investigation.

## Incident Timeline

| Date / Time        | Activity                               |
| ------------------ | -------------------------------------- |
| 28 Aug 2026        | Connectivity test (ping) from Kali     |
| 28 Aug 2026 13:31  | Nmap scan on port 445                  |
| 28 Aug 2026 ~10:54 | Multiple SMB brute force attempts      |
| 28 Aug 2026        | Event ID 4625 logged on Windows Server |
| 28 Aug 2026        | Failed logons visible in Splunk        |
| 28 Aug 2026        | One successful EventCode 4624 observed |

## Splunk Dashboard

A custom Splunk dashboard was created to support the detection and investigation of brute-force authentication activity.

**Dashboard Name:** Brute Force Attack Detection & Investigation

The dashboard contains the following panels:

- **Failed Authentication Attempts**  
  Displays the volume of failed logon events (EventCode 4625) over time.

- **Top Attacking IPs**  
  Shows the source IP addresses responsible for the highest number of failed authentication attempts.  
  The primary attacker IP identified was **192.168.56.103** (Kali Linux).

- **Targeted Accounts**  
  Lists the accounts that received the most failed logon attempts.  
  The main targeted account was **soc_test**.

- **Successful Logins**  
  Displays successful authentication events (EventCode 4624) for further investigation.

- **Account Lockouts**  
  Monitors whether any accounts were locked as a result of the failed attempts.

- **Authentication Timeline**  
  Provides a chronological view of both failed (4625) and successful (4624) authentication events.

## MITRE ATT&CK Mapping

**Tactic:** Credential Access

**Technique:** T1110 – Brute Force

**Sub-technique:** T1110.001 – Password Guessing

The activity simulated password guessing against a Windows account and generated multiple failed authentication events that were detected and investigated using Windows Event Viewer and Splunk.

## Findings

The investigation identified the following:

* Multiple failed authentication attempts originated from `192.168.56.103`, the Kali Linux machine.
* The target account was `soc_test` in the `CORP` domain.
* The brute force activity was visible in both Windows Event Viewer and Splunk.
* Multiple **Event ID 4625** events confirmed failed authentication attempts.
* One **Event ID 4624** successful authentication event was also recorded.
* The authentication activity provided sufficient evidence to investigate the incident as a simulated brute force scenario.

## Simulated SOC Response

The following SOC investigation steps were performed:

1. Confirmed the source IP address: `192.168.56.103`.
2. Identified the targeted account: `soc_test`.
3. Verified the volume of failed authentication attempts.
4. Investigated Windows Event ID 4625 events.
5. Searched Splunk for corresponding failed logon activity.
6. Checked for successful authentication using Event ID 4624.
7. Correlated failed and successful authentication events.
8. Documented the incident and investigation findings.
9. Recommended additional account protection and monitoring controls.

## Recommended Mitigations

Based on the investigation, the following controls are recommended:

* Implement an appropriate account lockout policy.
* Monitor repeated failed authentication attempts.
* Create a real-time Splunk alert for suspicious EventCode 4625 activity.
* Investigate successful logons following multiple failed attempts.
* Monitor authentication activity from unusual source IP addresses.
* Establish thresholds for detecting repeated password guessing.
* Continue forwarding Windows security logs to Splunk for centralized monitoring.

## Lessons Learned

This investigation provided several practical SOC analyst lessons:

**1. Event ID 4625 is critical for detecting failed authentication activity.**

Repeated 4625 events can provide an early indicator of password guessing or brute force activity.

**2. Failed and successful logons should be correlated.**

A series of failed authentication attempts followed by Event ID 4624 can be particularly important because it may indicate that an attacker eventually obtained valid credentials.

**3. Centralized logging improves investigation speed.**

Forwarding Windows security logs into Splunk made it easier to search, correlate, and investigate authentication activity from a centralized platform.

**4. Source and target correlation matters.**

Identifying the source IP, target account, workstation, and logon type provides important context during an authentication investigation.

## Future Improvements

The lab can be expanded with the following improvements:

* Create a real-time Splunk alert for repeated EventCode 4625 events.
* Build a dedicated brute force detection dashboard.
* Add failed versus successful authentication visualizations.
* Add source IP reputation and enrichment.
* Test the detection against RDP brute force activity.
* Create additional detections for suspicious EventCode 4624 activity.
* Develop a complete incident response workflow.
* Add automated alerting and response capabilities.

## Evidence

All supporting evidence is stored in the project repository:

```text
screenshots/       → Attack and detection screenshots
spl-queries/       → Detection SPL queries
architecture/      → Lab architecture diagram
incident-report/   → Detailed incident report
```

## Conclusion

This project demonstrated a complete simulated SOC investigation of a Windows brute force attack using **Kali Linux, Windows Server, Windows Event Viewer, and Splunk**.

The exercise covered attack simulation, Windows security event analysis, log forwarding, Splunk investigation, SPL detection logic, authentication correlation, MITRE ATT&CK mapping, incident documentation, and recommended security controls.

The key takeaway was that effective SOC monitoring is not simply about detecting failed logins. It is about **correlating authentication events, understanding the attack timeline, identifying suspicious patterns, and determining whether a successful authentication occurred.**
