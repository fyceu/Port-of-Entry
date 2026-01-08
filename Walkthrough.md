## Table of Contents

- Summary of Findings
- Threat Hunt
	- Flag 1: Initial Access - Remote Access Source
	- Flag 2: Initial Access - Compromised User Account
	- Flag 3: Discovery - Network Reconnaissance
	- Flag 4: Defense Evasion - Malware Staging Directory
	- Flag 5: Defense Evasion - File Extension Exclusions
	- Flag 6: Defense Evasion - File Path Exclusions
	- Flag 7: Defense Evasion - Download Utility Abuse
	- Flag 8: Persistence - Scheduled Task Name
	- Flag 9: Persistence - Scheduled Task Target
	- Flag 10: Command & Control - C2 Server Address
	- Flag 11: Command & Control - C2 Communication Port
	- Flag 12: Credential Access - Credential Theft Tool
	- Flag 13: Credential Acess - Memory Extraction Module
	- Flag 14: Collection - Data Staging Archive
	- Flag 15: Exfiltration - Exfiltration Channel
	- Flag 16: Anti-Forensics - Log Tampering
	- Flag 17: Impact - Persistence Account
	- Flag 18: Execution - Malicious Script
	- Flag 19: Lateral Movement - Secondary Target
	- Flag 20: Lateral Movement - Remote Access Tool
- Timeline
- MITRE ATT&CK Framework
- Indicators of Compromise (IOCs)
- Lessons Learned 
- Recommendations

## Summary of Findings
Below is a dropdown of all the findings for this threat hunt. To see my investigation steps, skip to the next section **Threat Hunt**

| Flag |                                 Objective                                  |                  Finding                  |           Timestamp            |
| :--: | :------------------------------------------------------------------------: | :---------------------------------------: | :----------------------------: |
|  1   | Identify the source IP address of the Remote Desktop Protocol connection?  |              `88.97.178.12`               | `2025-11-19T18:36:18.503997Z`  |
|  2   |     Identify the user account that was compromised for initial access?     |               `kenji.sato`                | `2025-11-19T18:36:18.503997Z`  |
|  3   |  Identify the command and argument used to enumerate network neighbours?   |                 `arp -a`                  | `2025-11-19T19:04:01.773778Z`  |
|  4   |      Identify the PRIMARY staging directory where malware was stored?      |       `C:\ProgramData\WindowsCache`       | `2025-11-19T19:05:33.7665036Z` |
|  5   |   How many file extensions were excluded from Windows Defender scanning?   |                    `3`                    | `2025-11-19T18:49:29.1787135Z` |
|  6   |  What temporary folder path was excluded from Windows Defender scanning?   | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` | `2025-11-19T18:49:27.6830204Z` |
|  7   | Identify the Windows-native binary the attacker abused to download files?  |               `cerutil.exe`               | `2025-11-19T19:06:58.5778439Z` |
|  8   |      Identify the name of the scheduled task created for persistence?      |          `Windows Update Check`           | `2025-11-19T19:07:46.9796512Z` |
|  9   |       Identify the executable path configured in the scheduled task?       | `C:\ProgramData\WindowsCache\svchost.exe` | `2025-11-19T19:07:46.9796512Z` |
|  10  |         Identify the IP address of the command and control server?         |              `78.141.196.6`               | `2025-11-19T19:11:04.1766386Z` |
|  11  | Identify the destination port used for command and control communications? |                   `443`                   | `2025-11-19T19:11:04.1766386Z` |
|  12  |           Identify the filename of the credential dumping tool?            |                 `mm.exe`                  | `2025-11-19T19:07:22.8551193Z` |
|  13  |      Identify the module used to extract logon passwords from memory?      |        `sekurlsa::logonpasswords`         | `2025-11-19T19:08:26.2804285Z` |
|  14  |    Identify the compressed archive filename used for data exfiltration?    |             `export-data.zip`             | `2025-11-19T19:08:58.0244963Z` |
|  15  |         Identify the cloud service used to exfiltrate stolen data?         |                 `discord`                 | `2025-11-19T19:09:21.4234133Z` |
|  16  |       Identify the first Windows event log cleared by the attacker?        |                `Security`                 | `2025-11-19T19:11:39.0934399Z` |
|  17  |      Identify the backdoor account username created by the attacker?       |                 `support`                 | `2025-11-19T19:09:48.8977132Z` |
|  18  |   Identify the PowerShell script file used to automate the attack chain?   |               `wupdate.ps1`               | `2025-11-19T18:49:48.7079818Z` |
|  19  |             What IP address was targeted for lateral movement?             |               `10.1.0.188`                | `2025-11-19T19:10:42.057693Z`  |
|  20  |         Identify the remote access tool used for lateral movement?         |                `mstsc.exe`                | `2025-11-19T19:10:42.057693Z`  |
|      |                                                                            |                                           |                                |

## Threat Hunt

### 🚩 Flag 1: Initial Access - Remote Access Source
Objective: **Identify the source IP address of the Remote Desktop Protocol connection?**

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

KQL Query: 
```KQL
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project Timestamp, AccountName, ActionType, LogonType, RemoteIPType, RemoteIP, RemotePort
| sort by Timestamp asc
```
### 🚩 Flag 2: Initial Access - Compromised User Account
### 🚩 Flag 3: Discovery - Network Reconaissance
### 🚩 Flag 4: Defense Evasion - Malware Staging Directory
### 🚩 Flag 5: Defense Evasion - File Extension Exclusions
### 🚩 Flag 6: Defense Evasion - File Path Exclusions
### 🚩 Flag 7: Defense Evasion - Download Utility Abuse
### 🚩 Flag 8: Persistence - Scheduled Task Name
### 🚩 Flag 9: Persistence - Scheduled Task Target
### 🚩 Flag 10: Command & Control - C2 Server Address
### 🚩 Flag 11: Command & Control - C2 Communication Port
### 🚩 Flag 12: Command & Control - Credential Theft Tool
### 🚩 Flag 13: Credential Access - Memory Extraction Module
### 🚩 Flag 14: Collection - Data Staging Archive
### 🚩 Flag 15: Exfiltration - Exfiltration Channel
### 🚩 Flag 16: Anti-Forensics - Log Tampering 
### 🚩 Flag 17: Impact - Persistence Account
### 🚩 Flag 18: Execution - Malicious Script 
### 🚩 Flag 19: Lateral Movement - Secondary Target
### 🚩 Flag 20: Lateral Movement - Remote Access Tool

