//This rule detects instances where the script SyncAppvPublishingServer.vbs spawns command interpreters such as PowerShell, CMD, or WScript. While this script is part of the legitimate Microsoft App-V (Application Virtualization) framework. Threat actors have abused SyncAppvPublishingServer.vbs as a Living-off-the-Land Binary (LOLBIN) to execute malicious commands and bypass traditional security controls. In several attack campaigns (including fake CAPTCHA and clipboard-based execution attacks), adversaries trick users into running commands that invoke this script to launch PowerShell payloads or additional malware. 
//Reference: https://www.helpnetsecurity.com/2026/01/27/malware-delivery-via-windows-app-v-lolbin/
//Reference: https://thehackernews.com/2026/01/clickfix-attacks-expand-using-fake.html


DeviceProcessEvents
| where InitiatingProcessCommandLine has "SyncAppvPublishingServer.vbs"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe")
| project
   Timestamp,
   DeviceName,
   DeviceId,
   ReportId,
   AccountName,
   FileName,
   ProcessCommandLine,
   InitiatingProcessFileName,
   InitiatingProcessCommandLine
| order by Timestamp desc
