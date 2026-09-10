# PowerShell Detection Logic

## Purpose

**The purpose of this detection is to identify PowerShell activity containing characteristics that may warrant additional security investigation.**

The detection is based on Windows PowerShell Script Block Logging and Event ID 4104.

## Primary Telemetry

**The primary telemetry source is:**

```text
Windows Server 2025
        |
        v
PowerShell Operational Log
        |
        v
Event ID 4104
        |
        v
Splunk Universal Forwarder
        |
        v
Splunk Enterprise
```

## Detection Indicators

**The detection searches for the following characteristics:**

### Encoded Command

```text
EncodedCommand
```

Encoded PowerShell can make command content less immediately visible to an analyst. Encoded commands can have legitimate uses, so additional context is required.

### Execution Policy Bypass

```text
ExecutionPolicy Bypass
```

An execution policy bypass can be a suspicious characteristic because it can be used to change the normal PowerShell execution policy behavior. It should be investigated in context.

### Hidden Window

```text
WindowStyle Hidden
```

Hidden PowerShell execution can be suspicious when there is no legitimate reason for the window to be hidden.

### Invoke Expression

```text
Invoke-Expression
```

Invoke Expression can dynamically execute PowerShell content and therefore may warrant investigation depending on the surrounding command and user context.

### Download String

```text
DownloadString
```

Download String can be associated with retrieving content from a remote location. Its presence should be investigated alongside network, process and user activity.

### Base64 Decoding

```text
FromBase64String
```

Base64 decoding can appear in legitimate software, but it can also be used to obfuscate command or script content.

## Detection SPL

```spl
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
| sort - count
```

## Detection Philosophy

**The detection intentionally does not classify every PowerShell event as malicious.**

Instead, it identifies characteristics that increase investigative interest. A SOC analyst should evaluate:

```text
Indicator
   |
   v
User
   |
   v
Host
   |
   v
Timestamp
   |
   v
Command Content
   |
   v
Parent Process
   |
   v
Related Events
   |
   v
Final Assessment
```

## Risk Scoring

**The project also uses a simple risk scoring model.**

```spl
index=main EventCode=4104
| eval risk=0
| eval risk=if(match(_raw,"(?i)EncodedCommand"),risk+30,risk)
| eval risk=if(match(_raw,"(?i)ExecutionPolicy\s+Bypass"),risk+25,risk)
| eval risk=if(match(_raw,"(?i)WindowStyle\s+Hidden"),risk+20,risk)
| eval risk=if(match(_raw,"(?i)Invoke-Expression"),risk+20,risk)
| eval risk=if(match(_raw,"(?i)DownloadString"),risk+25,risk)
| eval risk=if(match(_raw,"(?i)FromBase64String"),risk+20,risk)
| where risk > 0
| table _time host User risk Message
| sort - risk
```

The risk score is intended to assist prioritization and is not a replacement for analyst investigation.

## MITRE ATT&CK

**The primary ATT&CK mapping is:**

```text
T1059.001
Command and Scripting Interpreter: PowerShell
```

The detection provides visibility into PowerShell execution and suspicious PowerShell characteristics.
