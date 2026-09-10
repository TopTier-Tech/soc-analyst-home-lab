# Lessons Learned

## 1. Endpoint logging is the foundation of SIEM detection

**A SIEM can only detect what it receives.**

PowerShell logging had to be enabled on Windows Server 2025 before meaningful PowerShell telemetry could be investigated in Splunk.

## 2. Event ID 4104 provides valuable PowerShell visibility

**PowerShell Script Block Logging and Event ID 4104 provide useful information for investigating PowerShell execution.**

The event can help an analyst understand what PowerShell activity occurred and when it happened.

## 3. Windows Event Viewer and Splunk provide different perspectives

**Windows Event Viewer confirms that an event exists locally on the endpoint.**

Splunk provides centralized visibility and allows the analyst to search and correlate events across the environment. The two systems therefore serve different but complementary purposes.

## 4. Log forwarding must be validated

**A Windows event existing in Event Viewer does not automatically mean that Splunk can see it.**

The complete ingestion pipeline must be validated:

```text
Windows Event Log
       |
       v
Universal Forwarder
       |
       v
Receiving Port
       |
       v
Splunk Enterprise
       |
       v
Correct Index
       |
       v
Correct Sourcetype
       |
       v
SPL Search
```

## 5. Field awareness is important in SPL

**SPL searches depend on the fields available in the indexed event.**

When a query returns no results, an analyst should inspect the raw event and verify the actual field names instead of assuming that every Windows event has identical field extraction. Using `_raw` for certain searches can provide a useful fallback when specific fields are unavailable.

## 6. PowerShell is not inherently malicious

**PowerShell is a legitimate Windows administration tool.**

Commands such as:

```powershell
Get-Process
Get-Service
Get-Date
```

can be completely normal. A SOC detection should therefore focus on suspicious characteristics and environmental context rather than simply detecting the presence of PowerShell.

## 7. Multiple telemetry sources improve investigation

**Event ID 4104 provides PowerShell script block visibility.**

Event ID 4688 can provide process creation information. Windows Security events can provide additional authentication and privilege information. Correlating multiple sources gives an analyst a stronger investigation picture than relying on one event type.

## 8. Risk scoring helps prioritize investigation

**A large environment can generate many PowerShell events.**

A risk scoring approach can help an analyst prioritize events containing multiple suspicious characteristics. The score should support analyst decision making rather than automatically determine whether activity is malicious.

## 9. Dashboards turn raw logs into useful security visibility

**A dashboard allows an analyst to quickly identify:**

- PowerShell activity volume
- Activity over time
- Users generating PowerShell events
- Hosts generating PowerShell events
- Suspicious indicators
- Recent activity

This makes the telemetry easier to monitor and investigate.

## 10. Troubleshooting is part of SOC work

**One of the practical lessons from this project was that successful detection depends on the entire telemetry pipeline.**

When an event appears in Windows Event Viewer but not in Splunk, the analyst needs to investigate:

```text
inputs.conf
Universal Forwarder
Forwarding configuration
Receiving port
Index
Sourcetype
Field extraction
SPL query
```

This is an important operational skill for anyone working with a SIEM.

## Final Lesson

**The most important lesson from this project is that effective SOC monitoring is not simply about writing searches.**

It requires understanding the entire chain:

```text
Endpoint
   ↓
Logging
   ↓
Collection
   ↓
Forwarding
   ↓
SIEM
   ↓
Detection
   ↓
Investigation
   ↓
Correlation
   ↓
Risk Assessment
   ↓
Analyst Decision
```

This project provided practical experience across that complete workflow.
