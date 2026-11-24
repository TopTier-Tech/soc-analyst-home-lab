# Lab Architecture

## Overview

This project was conducted in a controlled cybersecurity laboratory environment designed to simulate a Tier 1 Security Operations Center phishing investigation.

The environment allows a simulated phishing email to be investigated from the initial email artifact through potential user interaction, endpoint telemetry, SIEM analysis, and incident response.

## Lab Components

### 1. Outlook

Outlook was used to present the simulated phishing email to the target user.

The email contained intentionally suspicious characteristics, including a lookalike sender domain, urgent account verification language, and a suspicious URL.

### 2. Windows Endpoint

The Windows endpoint represents the workstation of the user who received the phishing email.

Windows Event Logs and Sysmon provide endpoint telemetry for investigating process creation, network connections, file creation, and other security-relevant activity.

### 3. Sysmon

Sysmon provides detailed endpoint telemetry that can be used to investigate activity associated with potential phishing interaction.

Relevant telemetry includes:

- Process creation
- Network connections
- File creation
- Process relationships
- Other endpoint activity

### 4. Splunk Enterprise

Splunk Enterprise serves as the Security Information and Event Management (SIEM) platform for the laboratory.

Windows and Sysmon telemetry is forwarded to Splunk for searching, correlation, investigation, and evidence collection.

### 5. Kali Linux

Kali Linux is part of the isolated cybersecurity laboratory environment and may be used to support controlled security testing and investigation activities.

No unauthorized external systems are targeted as part of this project.

### 6. SOC Analyst

The analyst investigates the phishing alert by:

- Reviewing the email
- Extracting indicators of compromise
- Performing threat intelligence enrichment
- Investigating user interaction
- Reviewing endpoint telemetry
- Searching Splunk
- Building an incident timeline
- Mapping activity to MITRE ATT&CK
- Recommending containment and recovery actions

## Evidence Flow

The investigation follows this general evidence flow:

```text
Simulated Phishing Email
          ↓
       Outlook
          ↓
     User Interaction
          ↓
   Windows Endpoint
          ↓
 Windows Event Logs + Sysmon
          ↓
   Splunk Enterprise
          ↓
   SOC Investigation
          ↓
 IOC Analysis + Correlation
          ↓
MITRE ATT&CK + Timeline
          ↓
 Incident Response
          ↓
   Final SOC Report
```

## Security Boundary

The project is performed in a controlled laboratory environment.

The phishing email, domains, URLs, and other artifacts used for the simulation are designed for security training and investigation purposes.

No real credentials are collected, and no unauthorized external systems are targeted.

## Architecture Diagram

The visual architecture diagram for this project is available in:

`architecture.png`
