Suspicious PowerShell Activity Detection and Investigation
Overview

This project demonstrates the detection and investigation of PowerShell activity on a Windows Server 2025 endpoint using Splunk Enterprise and the Splunk Universal Forwarder.

The objective was to build a practical Security Operations Center monitoring workflow that captures PowerShell execution telemetry, forwards Windows Event Logs to Splunk, identifies potentially suspicious PowerShell characteristics, investigates the associated activity, and presents the results through a Splunk dashboard.

The activity was performed in an isolated home lab using controlled and harmless PowerShell commands. No malware or destructive payloads were used.

The project focuses on the type of telemetry and investigation workflow that a Junior SOC Analyst or Tier 1 SOC Analyst would use when investigating suspicious PowerShell activity.

Project Objectives

The main objectives of this project were to:

Enable PowerShell logging on Windows Server 2025.
Capture PowerShell Script Block Logging events.
Monitor Event ID 4104.
Forward Windows PowerShell telemetry to Splunk Enterprise.
Develop SPL searches for PowerShell activity.
Identify potentially suspicious PowerShell characteristics.
Investigate PowerShell execution using Windows and Splunk telemetry.
Correlate PowerShell activity with process creation events.
Develop a risk scoring approach.
Build a Splunk dashboard for PowerShell monitoring.
Document the investigation and detection methodology.
Map the detection to the MITRE ATT&CK framework.
Lab Architecture
                    Kali Linux
                         |
                         |
                         v
              Windows Server 2025
                         |
             Windows Event Logs
                         |
                         v
              Splunk Universal
                  Forwarder
                         |
                    TCP 9997
                         |
                         v
                 Splunk Enterprise
                         |
              +----------+----------+
              |          |          |
              v          v          v
          Detection  Investigation Dashboard

The Windows Server 2025 machine served as the monitored endpoint.

Splunk Universal Forwarder collected the relevant Windows Event Logs and forwarded the telemetry to Splunk Enterprise.

Splunk Enterprise was used as the SIEM platform for searching, detection, investigation, visualization, and dashboard development.

Technologies Used
Technology	Purpose
Windows Server 2025	Monitored endpoint
PowerShell	Activity being monitored
Windows Event Viewer	Local event verification
Splunk Universal Forwarder	Log collection and forwarding
Splunk Enterprise	SIEM, detection, investigation and visualization
Kali Linux	Lab environment and security testing platform
SPL	Splunk Search Processing Language
VirtualBox	Isolated laboratory environment
Windows Logging Configuration

PowerShell logging was configured on Windows Server 2025 to provide visibility into PowerShell execution.

The following logging capabilities were used:

PowerShell Script Block Logging

Script Block Logging was enabled to capture PowerShell script block activity.

This logging capability generates Event ID 4104, which provides valuable visibility into PowerShell commands and script content.




PowerShell Module Logging

Module Logging was enabled to provide additional visibility into PowerShell module activity.




PowerShell Transcription

PowerShell Transcription was configured to provide additional execution visibility within the laboratory environment.




After configuring the logging policies, the updated policies were applied.




Controlled PowerShell Activity

Controlled PowerShell activity was generated on Windows Server 2025 to verify that the logging configuration was working correctly.

Examples of harmless commands used during testing included:

Get-Date
Get-Process
Get-Service
Get-NetTCPConnection
Write-Output "SOC PowerShell Detection Lab Test"

These commands were used only to generate legitimate PowerShell telemetry for the detection and investigation workflow.




PowerShell Event ID 4104

After generating PowerShell activity, the resulting Windows events were examined in Event Viewer.

Event ID 4104 was used as the primary telemetry source for PowerShell Script Block Logging.

The event provided visibility into:

Event timestamp
Host
User context
PowerShell execution
Script block information




Splunk Log Ingestion

The Splunk Universal Forwarder was configured to collect the Windows PowerShell Operational log and forward it to Splunk Enterprise.

The relevant Windows Event Log input was configured as:

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Microsoft-Windows-PowerShell/Operational

The PowerShell events were successfully received by Splunk Enterprise.




Basic PowerShell Detection

The initial detection search focused on identifying PowerShell Script Block Logging events.

index=main EventCode=4104
| table _time host EventCode Message
| sort - _time

This search provides a basic view of PowerShell Script Block Logging activity.

The search can be expanded to identify activity by host, user and timestamp.

PowerShell Activity Timeline

PowerShell activity was visualized over time to identify periods of increased PowerShell execution.

index=main EventCode=4104
| timechart count




Suspicious PowerShell Detection

The next stage of the investigation focused on characteristics that can indicate potentially suspicious PowerShell execution.

The detection logic looked for indicators such as:

Encoded PowerShell commands
Execution Policy Bypass
Hidden PowerShell windows
Invoke Expression
Download String
Base64 decoding

The detection search was designed to identify these indicators without executing malicious payloads.

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




The detection logic distinguishes normal PowerShell activity from activity containing characteristics that may require additional investigation.

PowerShell Risk Scoring

A risk scoring approach was developed to prioritize PowerShell events based on suspicious characteristics.

The following indicators were assigned weighted scores:

Indicator	Risk Score
Encoded Command	30
Execution Policy Bypass	25
Hidden Window	20
Invoke Expression	20
Download String	25
Base64 Decoding	20

The SPL used for the risk scoring model was:

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

The purpose of this scoring model was to demonstrate how multiple suspicious characteristics can be combined to prioritize events for analyst review.




Detection Summary

A summary search was used to identify suspicious indicators by host and user.

index=main EventCode=4104
| eval suspicious_indicator=case(
    match(_raw,"(?i)EncodedCommand"),"Encoded Command",
    match(_raw,"(?i)ExecutionPolicy\s+Bypass"),"Execution Policy Bypass",
    match(_raw,"(?i)WindowStyle\s+Hidden"),"Hidden Window",
    match(_raw,"(?i)Invoke-Expression"),"Invoke-Expression",
    match(_raw,"(?i)DownloadString"),"DownloadString",
    match(_raw,"(?i)FromBase64String"),"Base64 Decoding",
    true(),"Other"
)
| where suspicious_indicator!="Other"
| stats count by host User suspicious_indicator
| sort - count




Process Creation Investigation

PowerShell activity was also correlated with Windows process creation telemetry where available.

Windows Event ID 4688 was used to investigate process creation and identify PowerShell processes.

Example search:

index=main EventCode=4688
| search "powershell.exe"
| table _time host User New_Process_Name Creator_Process_Name Process_Command_Line
| sort - _time

The exact field names may vary depending on the Windows event parsing configuration.




Investigation Process

The investigation followed a structured SOC workflow:

PowerShell Activity Detected
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
Examine PowerShell Script Block
            |
            v
Identify Suspicious Indicators
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
Document Finding

The investigation focused on answering five core questions:

What happened?
When did it happen?
Which host generated the activity?
Which user account was involved?
Was the PowerShell activity legitimate or suspicious?

A detailed investigation document is available in:

documentation/investigation.md
Splunk Dashboard

A dedicated Splunk dashboard was created to provide centralized visibility into PowerShell activity.

The dashboard contains panels for:

Total PowerShell events
PowerShell activity over time
PowerShell activity by user
PowerShell activity by host
Suspicious PowerShell indicators
Recent PowerShell activity




The dashboard provides an analyst friendly view of PowerShell telemetry and allows suspicious activity to be identified more quickly.

Dashboard SPL
Total PowerShell Events
index=main EventCode=4104
| stats count
PowerShell Activity Over Time
index=main EventCode=4104
| timechart count
Activity by User
index=main EventCode=4104
| stats count by User
| sort - count
Activity by Host
index=main EventCode=4104
| stats count by host
| sort - count
Suspicious PowerShell Indicators
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
Recent PowerShell Activity
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
| table _time host User indicator
| sort - _time
Detection Logic

The detection logic is based on PowerShell characteristics that can warrant additional investigation.

The presence of one indicator does not automatically mean that an event is malicious.

For example, encoded PowerShell may be used by legitimate administrators or software.

Therefore, the detection is designed to provide an analyst with a starting point for investigation rather than automatically declaring an event malicious.

The investigation should consider:

User context
Host context
Time of execution
Parent process
Command content
Frequency of execution
Related Windows Security events
Process creation events
Other activity occurring around the same time
MITRE ATT&CK Mapping
T1059.001

Command and Scripting Interpreter: PowerShell

This project provides telemetry and detection capabilities for PowerShell activity associated with the Command and Scripting Interpreter technique.

PowerShell is widely used for legitimate Windows administration but can also be abused by attackers for execution, discovery, download activity and other post compromise operations.

The project therefore focuses on detecting suspicious characteristics rather than treating every PowerShell event as malicious.

Investigation Findings

The laboratory demonstrated that PowerShell Script Block Logging can provide valuable visibility into PowerShell execution.

Event ID 4104 was successfully used as a primary source of PowerShell telemetry for investigation.

The activity was forwarded from Windows Server 2025 through the Splunk Universal Forwarder into Splunk Enterprise, where SPL searches were used to identify and analyze PowerShell events.

The investigation workflow demonstrated how an analyst can move from basic event detection to contextual investigation using host, user, timestamp, script block and process information.

Lessons Learned

Several important SOC monitoring concepts were demonstrated during this project.

PowerShell logging is valuable

PowerShell can generate a large amount of useful security telemetry when appropriate logging is enabled.

Event ID 4104 is important

Script Block Logging provides valuable visibility into PowerShell script execution and is useful when investigating suspicious PowerShell activity.

SIEM visibility depends on ingestion

A security event existing in Windows Event Viewer does not automatically mean that it is available in Splunk.

The complete pipeline must work:

Windows Event Log
       |
       v
Universal Forwarder
       |
       v
Splunk Receiver
       |
       v
Index
       |
       v
SPL Search
Detection requires context

A PowerShell command should not automatically be classified as malicious simply because PowerShell was used.

User, host, timing, process context and command content must be considered together.

Risk scoring can improve prioritization

Combining multiple suspicious characteristics can help analysts prioritize events for investigation.

Troubleshooting is part of SOC work

During the project, troubleshooting log ingestion and field extraction was an important part of validating the monitoring pipeline.

This reinforced the importance of understanding both the endpoint and SIEM sides of security monitoring.

Future Improvements

Potential improvements to this laboratory include:

Creating Splunk alerts for high risk PowerShell activity.
Adding additional Windows Security telemetry.
Improving process creation correlation.
Adding Sysmon telemetry.
Building additional correlation searches.
Creating analyst investigation playbooks.
Adding automated alert enrichment.
Expanding detection coverage for PowerShell download activity.
Testing the detection against additional controlled scenarios.
Project Status

Completed

The project successfully demonstrated PowerShell logging, Windows Event ID 4104 monitoring, Splunk ingestion, suspicious activity detection, risk scoring, investigation and dashboard development within an isolated laboratory environment.

Disclaimer

This project was conducted in an isolated home laboratory for cybersecurity education and portfolio development.

All PowerShell activity used during the laboratory exercise was controlled and harmless.

No malware, destructive payloads or unauthorized systems were used.
