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
