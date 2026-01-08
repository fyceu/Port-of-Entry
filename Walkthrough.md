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

So within `DevicelogonEvents`, I would be searching for successful logon events coming from a public IP address during our incident timeframe. Public IP addresses would be coming from outside the organization's network.

```KQL
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project Timestamp, AccountName, ActionType, LogonType, RemoteIPType, RemoteIP, RemotePort
| sort by Timestamp asc
```
<img width="1269" height="337" alt="Screenshot 2026-01-07 at 6 24 33 PM" src="https://github.com/user-attachments/assets/bc62ef5a-df06-4250-9a32-347a4dff3723" />

From my query, I found a single public IP address, `88.97.178.12` that was able to succesfully remote into a user account. 

Flag: `88.97.178.12` <br>
Timestamp: `2025-11-19T18:36:18.503997Z`

### 🚩 Flag 2: Initial Access - Compromised User Account
Objective: **Identify the user account that was compromised for initial access?**

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

Using information gathered from the previous KQL query, the attacker was able to successfully login to the user account `kenji.sato`

Flag: `kenji.sato` <br> 
Timestamp: `2025-11-19T18:36:18.503997Z`

### 🚩 Flag 3: Discovery - Network Reconaissance
Objective: **Identify the command and argument used to enumerate network neighbours?**

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

ABCABCABC
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("arp", "ipconfig", "nbstat", "route")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

Flag: `arp -a` <br>
Timestamp: `2025-11-19T19:04:01.773778Z``

### 🚩 Flag 4: Defense Evasion - Malware Staging Directory
Objective: **Identify the PRIMARY staging directory where malware was stored?**

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

Flag: `C:\ProgramData\WindowsCache` <br>
Timestamp: `2025-11-19T19:05:33.7665036Z`

### 🚩 Flag 5: Defense Evasion - File Extension Exclusions
Objective: **How many file extensions were excluded from Windows Defender scanning?**

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.


Flag: `3` <br>
Timestamp: `2025-11-19T18:49:29.1787135Z`

### 🚩 Flag 6: Defense Evasion - Temporary Folder Exclusion
Objective: **What temporary folder path was excluded from Windows Defender scanning?**

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.


Flag: `C:\Users\KENJI~1.SAT\AppData\Local\Temp` <br>
Timestamp: `2025-11-19T18:49:27.6830204Z`

### 🚩 Flag 7: Defense Evasion - Download Utility Abuse
Objective: **Identify the Windows-native binary the attacker abused to download files?**

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

Flag: ``certutil.exe`` <br>
Timestamp: `2025-11-19T19:06:58.5778439Z`

### 🚩 Flag 8: Persistence - Scheduled Task Name
Objective: **Identify the name of the scheduled task created for persistence?**

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

Flag: `Windows Update Check` <br>
Timestamp: `2025-11-19T19:07:46.9796512Z`

### 🚩 Flag 9: Persistence - Scheduled Task Target
Objective: **Identify the executable path configured in the scheduled task?

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

Flag: `C:\ProgramData\WindowsCache\svchost.exe` <br>
Timestamp: `2025-11-19T19:07:46.9796512Z`

### 🚩 Flag 10: Command & Control - C2 Server Address
Objective: **Identify the IP address of the command and control server?**

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

Flag: `78.141.196.6` <br>
Timestamp: `2025-11-19T19:11:04.1766386Z`

### 🚩 Flag 11: Command & Control - C2 Communication Port
Objective: **Identify the destination port used for command and control communications?**

C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.


Flag: `443` <br>
Timestamp: `2025-11-19T19:11:04.1766386Z`

### 🚩 Flag 12: Command & Control - Credential Theft Tool
Objective: **Identify the filename of the credential dumping tool?**

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.


Flag: `mm.exe` <br>
Timestamp: `2025-11-19T19:07:22.8551193Z`

### 🚩 Flag 13: Credential Access - Memory Extraction Module
Objective: **Identify the module used to extract logon passwords from memory?**

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.


Flag: `sekurlsa::logonpasswords` <br>
Timestamp: `2025-11-19T19:08:26.2804285Z`

### 🚩 Flag 14: Collection - Data Staging Archive
Objective: **Identify the compressed archive filename used for data exfiltration?**

Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

Flag: `export-data.zip` <br>
Timestamp: `2025-11-19T19:08:58.0244963Z`

### 🚩 Flag 15: Exfiltration - Exfiltration Channel
Objective: **Identify the cloud service used to exfiltrate stolen data?**

Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.


Flag: `discord` <br>
Timestamp: `2025-11-19T19:09:21.4234133Z`

### 🚩 Flag 16: Anti-Forensics - Log Tampering 
Objective: **Identify the first Windows event log cleared by the attacker?**

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.


Flag: `Security` <br>
Timestamp: `2025-11-19T19:11:39.0934399Z`

### 🚩 Flag 17: Impact - Persistence Account
Objective: **Identify the backdoor account username created by the attacker?**

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

Flag: `support` <br>
Timestamp: `2025-11-19T19:09:48.8977132Z`

### 🚩 Flag 18: Execution - Malicious Script 
Objective: **Identify the PowerShell script file used to automate the attack chain?**

Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

Flag: `wupdate.ps1` <br>
Timestamp: `2025-11-19T18:49:48.7079818Z`

### 🚩 Flag 19: Lateral Movement - Secondary Target
Objective: **What IP address was targeted for lateral movement?**

Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

Flag: `10.1.0.188` <br>
Timestamp: `2025-11-19T19:10:42.057693Z`

### 🚩 Flag 20: Lateral Movement - Remote Access Tool
Objective: **Identify the remote access tool used for lateral movement?**

Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

Flag: `mstsc.exe` <br>
Timestamp: `2025-11-19T19:10:42.057693Z`

