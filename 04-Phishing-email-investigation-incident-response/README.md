# Phishing Email Investigation & Incident Response

## Overview

This project simulates a Tier 1 SOC investigation of a suspected phishing email.

The investigation covers the complete workflow from initial email triage through IOC extraction, threat intelligence, endpoint investigation, Splunk correlation, MITRE ATT&CK mapping, incident response, and final reporting.

## Investigation Objective

The objective was to determine whether the email represented a phishing attempt, identify relevant indicators of compromise, investigate potential user and endpoint activity, and document appropriate incident response actions.

## Environment

- Splunk Enterprise
- Windows
- Windows Event Logs
- Sysmon
- Outlook
- Kali Linux
- MITRE ATT&CK
- Threat intelligence resources

## Investigation Workflow

```text
Phishing Email
      ↓
Email Analysis
      ↓
IOC Extraction
      ↓
Threat Intelligence
      ↓
User Interaction
      ↓
Endpoint Investigation
      ↓
Splunk Investigation
      ↓
Timeline Reconstruction
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Response
      ↓
Final SOC Report
```

## Key Findings

The email demonstrated multiple phishing characteristics, including:

- Lookalike sender domain
- Brand impersonation
- Urgency
- Account verification pressure
- Suspicious external URL

The investigation then evaluated whether the email resulted in user interaction or suspicious endpoint activity.

## IOC Summary

| Type | Indicator |
|---|---|
| Email | security@micr0soft-example.com |
| Domain | micr0soft-example.com |
| URL | https://login-m365-verification.example |

## MITRE ATT&CK

The phishing activity was mapped to:

- T1566 — Phishing
- T1566.002 — Spearphishing Link

Additional techniques were mapped only where corresponding behavior was supported by investigation evidence.

## Investigation Documentation

### Project Overview
[Project Overview](01-project-overview/project-overview.md)

### Objectives
[Project Objectives](01-project-overview/objectives.md)

### Email Analysis
[Email Analysis](04-email-analysis/email-analysis.md)

### IOC Analysis
[IOC Analysis](05-ioc-analysis/ioc-analysis.md)

### Threat Intelligence
[Threat Intelligence](06-threat-intelligence/threat-intelligence.md)

### User Interaction
[User Interaction](07-user-interaction/user-interaction.md)

### Endpoint Investigation
[Endpoint Investigation](08-endpoint-investigation/endpoint-investigation.md)

### Splunk Investigation
[Splunk Investigation](09-splunk-investigation/splunk-investigation.md)

### Incident Timeline
[Incident Timeline](10-incident-timeline/timeline.md)

### MITRE ATT&CK Mapping
[MITRE ATT&CK](11-mitre-attack/mitre-mapping.md)

### Incident Response
[Incident Response](12-incident-response/incident-response.md)

### Final Incident Report
[Incident Report](13-incident-report/incident-report.md)

## Evidence

Screenshots and supporting evidence are available in the [screenshots](screenshots/) directory.

## Analyst Conclusion

The investigation demonstrated a structured SOC Tier 1 approach to phishing triage, IOC analysis, endpoint investigation, SIEM correlation, threat mapping, and incident response.

The project emphasizes evidence-based analysis rather than relying on a single indicator to determine whether an email is malicious.

