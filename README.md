# Port of Entry

<p align="center">
  <img width="400" height="450" alt="image" src="https://github.com/user-attachments/assets/c98c7902-c938-42b1-962c-7989560bb1ff" />
</p>

## Incident Overview
INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社 <br>

**COMPANY**: Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

**SITUATION**: Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

**Compromised Systems**:
- AZUKI-SL (IT admin workstation)

**Evidence Available**:
- Microsoft Defender for Endpoint logs

Investigate the compromised system using the captured endpoint logs to determine a timeline of the attacker's activity and provide answers to these questions to leadership 
- Initial access method?
- Compromised accounts?
- Data stolen?
- Exfiltration method?
- Persistent access remaining?

A full walkthrough of this lab can be read [here](https://github.com/fyceu/Port-of-Entry/blob/main/Walkthrough.md)

## Tech Stack
<img width="50" height="50" alt="azure" src="https://github.com/user-attachments/assets/fd2866b6-d2fa-4e61-bf55-0b20d63fca5e" />
<img width="50" height="50" alt="windows logo" src="https://github.com/user-attachments/assets/5b714048-8f2e-4753-b68a-7aa699b5ef38" />
<img width="50" height="50" alt="icons8-windows-defender-48" src="https://github.com/user-attachments/assets/41507be1-eadc-440c-b577-ccbf835e91e3" />
<img width="50" height="50" alt="Sentinel" src="https://github.com/user-attachments/assets/d3204768-1ac1-4493-b5f6-2bd74ab191d2" />
<img width="50" height="50" alt="KQL" src="https://github.com/user-attachments/assets/7e9d871a-0391-43be-a826-08486ef1d562" />
<img width="200" height="200" alt="virusTotal" src="https://github.com/user-attachments/assets/f3d7cb97-d890-4458-abbb-fd29cde3d7a9" />

- Microsoft Azure
- Windows 11
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- KQL
- VirusTotal

## Executive Summary
This investigation analyzed a security incident in which an attacker gained access to a Windows system using stolen employee login credentials. Once inside, the attacker quietly disabled security protections, downloaded malicious tools, and collected sensitive data.

The attacker created hidden folders and scheduled tasks to maintain access, extracted stored passwords, and compressed the collected data into a single file. That data was then sent outside the organization using a trusted online service. Before leaving, the attacker attempted to erase evidence and used the compromised system to connect to another internal machine.

A full investigation walkthrough can be read [here](https://github.com/fyceu/Port-of-Entry/blob/main/Walkthrough.md)

<p align="center">
  <img width="1000" height="720" alt="image" src="https://github.com/user-attachments/assets/47caf497-f59c-4319-bd8f-dbfea1f8ae37" />
</p>

## Lessons Learned and Security Recommendations
### Stolen Credentials enabled external access
The attacker was able to easily access the network by using valid credentials of user account kenji.sato. This highlights that credential compromise alone is enough for anyone to gain unauthorized access within the environment.
- Enforce Multi-factor Authentication (MFA) for RDP access
- Restrict RDP exposure through VPN-only access
- Monitor and alert successful RDP logon from public IP addresses

### Windows Built-in Tools utilized
The attacker leveraged trusted binaries (certutil.exe, curl.exe, schtasks.exe, and wevutil.exe) to stage and execute their attack. These can be difficult to track since they have legitimate use cases.

- Restrict LOLbins from executing in unusual file locations such as Temp directories
- Monitor and alert for unsuual command line usage

### Windows Defender Bypassed
The attacker was able to add exlcusions to both File extensions and directories. This prevents Windows Defender from scanning and detecting malicious files in these directories.

- Restrict Windows Defender exclusions from Non-Admnistrators
- Monitor and alert of new exclusions


### Persistence Tasks and Accounts
The attacker was able to create a scheduled task Windows Update Check which was set to run daily at 0200. Additionally, they were able to create the local user account support, adding them to the local adminsitrator group. These two mechanisms provided the attacker with persistence within the system even if other files of their attack were removed from the system.

- Routinely audit scheduled tasks and local administrator accounts
- Restrict local account creation from non-administrator local accounts

### Anti-forensics Activity
The attacker tried hiding their trakcs by clearing Windows Event logs for Security, System, and Application. This can make it difficult to track activity througgh their system during an incident or threat hunt

- Ensure logs are forwarded to SIEM or log collector (retention length based on company policy)
- Monitor and alert on attempts to clear logs

Determination of these findings and recommendations can be derived from the investigation walkthrough [here](https://github.com/fyceu/Port-of-Entry/blob/main/Walkthrough.md)
