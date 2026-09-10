# PowerShell Activity Investigation

## Investigation Overview

This investigation focused on identifying and analyzing PowerShell activity generated on Windows Server 2025 and forwarded to Splunk Enterprise.

The objective was to determine:

- What PowerShell activity occurred
- Which host generated it
- Which user was associated with the activity
- When the activity occurred
- Whether the observed characteristics required additional investigation

The investigation was performed in an isolated cybersecurity home laboratory.

## Investigation Workflow

Detect PowerShell Activity
        |
        v
Review Event ID 4104
        |
        v
Identify Host
        |
        v
Identify User
        |
        v
Review Timestamp
        |
        v
Review Script Block
        |
        v
Search for Suspicious Indicators
        |
        v
Review Related Windows Events
        |
        v
Correlate Process Creation
        |
        v
Determine Risk
        |
        v
Document Findings
## Step 1: Identify PowerShell Activity

The initial search focused on Windows Event ID 4104.

index=main EventCode=4104
| table _time host EventCode Message
| sort - _time

Event ID 4104 was used because PowerShell Script Block Logging records script block activity through this event.

## Step 2: Identify the Host

The host associated with the PowerShell event was reviewed.

index=main EventCode=4104
| stats count by host
| sort - count

This establishes which endpoint generated the PowerShell activity.

## Step 3: Identify the User

The associated user information was reviewed where the field was available.

index=main EventCode=4104
| stats count by User
| sort - count

User context is important because PowerShell activity must be evaluated in relation to the account that initiated it.

## Step 4: Review the Timestamp

The event timestamp was reviewed to establish when the PowerShell activity occurred.

The timestamp can then be used to search for related Windows Security and process creation events occurring around the same period.

## Step 5: Examine Script Block Information

The PowerShell Script Block content was reviewed to understand what activity had been executed.

The investigation focused on identifying potentially suspicious characteristics rather than treating PowerShell execution itself as malicious.

## Step 6: Search for Suspicious Indicators

The investigation searched for characteristics including:

- Encoded commands
- Execution Policy Bypass
- Hidden PowerShell windows
- Invoke-Expression
- Download String
- Base64 decoding

Example search:

index=main EventCode=4104
| eval indicator=case(
    match(_raw,"(?i)EncodedCommand"),"Encoded Command",
    match(_raw,"(?i)ExecutionPolicy\s+Bypass"),"Execution Policy Bypass",
    match(_raw,"(?i)WindowStyle\s+Hidden"),"Hidden Window",
    match(_raw,"(?i)Invoke-Expression"),"Invoke-Expression",
    match(_raw,"(?i)DownloadString"),"DownloadString",
    match(_raw,"(?i)FromBase64String"),"Base64 Decoding",
    true(),"Normal PowerShell"
)
| stats count by indicator
## Step 7: Correlate Process Creation

Where process creation telemetry was available, Windows Event ID 4688 was reviewed.

index=main EventCode=4688
| search "powershell.exe"
| table _time host User New_Process_Name Creator_Process_Name Process_Command_Line
| sort - _time

This provides additional context around the process that launched PowerShell.

## Step 8: Establish a Timeline

PowerShell events and related security events were arranged chronologically.

The timeline helps determine whether the PowerShell activity occurred as an isolated administrative action or as part of a larger sequence of events.

## Step 9: Risk Assessment

Suspicious indicators were assigned risk values to assist with prioritization.

The risk model considered:
| Indicator | Score |
|---|---|
| Encoded Command | 30 |
| Execution Policy Bypass | 25 |
| Hidden Window | 20 |
| Invoke-Expression | 20 |
| Download String | 25 |
| Base64 Decoding | 20 |

The score was used as an analytical aid rather than an automatic malicious classification.

## Investigation Result

The investigation successfully demonstrated the ability to collect, search, and analyze PowerShell Script Block Logging telemetry from Windows Server 2025 in Splunk Enterprise.

The controlled activity used for the project was intentionally harmless.

The investigation demonstrated how a SOC analyst can progress from a PowerShell event to a broader investigation involving:

- Host
- User
- Timestamp
- Script Block
- Suspicious characteristics
- Process creation
- Related Windows events
- Risk assessment

## Analyst Conclusion

PowerShell activity should not automatically be classified as malicious.

PowerShell is a legitimate Windows administration tool and is frequently used by system administrators and applications. The correct SOC approach is to investigate the context surrounding the execution and determine whether the observed behavior is expected for the user, host, and environment.

This project demonstrates that Event ID 4104 provides valuable visibility for that investigation process.
