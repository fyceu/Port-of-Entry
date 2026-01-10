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

A full walkthrough of this lab can be read [here]().

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

This incident demonstrates how a single compromised account, combined with weak system protections, can lead to unauthorized access, data theft, and further spread inside a network.

A full investigation walkthrough can be read [here]().
