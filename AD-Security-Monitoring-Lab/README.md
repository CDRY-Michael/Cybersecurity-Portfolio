# AD Security Monitoring Lab

A home lab built to simulate common Active Directory attacks and detect them using a Splunk SIEM. The goal was to understand the full picture of each attack how it works from the attacker's side, what artifacts it leaves in Windows event logs, and how to detect it and to map each technique to MITRE ATT&CK.

This project was built as a self-directed learning exercise while studying for my BSc in Cybersecurity.

## Objectives

- Stand up a realistic AD environment (domain controller, workstation, attacker host, SIEM).
- Execute six common AD attacks against the domain.
- Forward Windows security and operational logs to Splunk and write detection queries for each attack.
- Document the detection logic and map each technique to MITRE ATT&CK.

## Environment

| Role               | OS                  | Details                                                                             |
| ------------------ | ------------------- | ----------------------------------------------------------------------------------- |
| Domain Controller  | Windows Server 2022 | `corp.local`, DC IP `192.168.40.10`, Splunk Universal Forwarder, Sysmon             |
| Workstation / SIEM | Windows 11          | Domain-joined (`192.168.40.129`), Splunk Enterprise (indexer + search head), Sysmon |
| Attacker           | Kali Linux          | `192.168.40.130` — Kerbrute, CrackMapExec, Impacket, Evil-WinRM, Hashcat            |

Network: VMware custom VMnet, `192.168.40.0/24` (isolated). Logs from the DC and workstation are forwarded to Splunk on the Windows 11 host, where detection queries are run against the Security, PowerShell/Operational, and Sysmon/Operational channels.

See [Architecture/](Architecture/) for the full topology diagram and configuration notes.

## Attack Scenarios

Each scenario folder contains an attack walkthrough, a `detection.md` (event IDs + Splunk queries + IOCs), and supporting screenshots.

| # | Attack | Key Event IDs | MITRE Technique |
|---|--------|---------------|-----------------|
| 01 | Brute Force (Guessing + Spraying) | 4625, 4740, 4771 | T1110.001, T1110.003 |
| 02 | Domain Account Creation | 4720, 4728 | T1136.002 |
| 03 | Additional Local/Domain Groups | 4728, 4732, 4756 | T1098 |
| 04 | Kerberoasting | 4769 | T1558.003 |
| 05 | PowerShell Execution | 4104, Sysmon EID 1 | T1059.001 |
| 06 | Privilege Escalation (DCSync) | 4662 | T1003.006 |

## Repo Structure

```
AD-Security-Monitoring-Lab/
├── Architecture/              # Network topology and environment setup
├── Attack-Scenarios/          # One folder per attack (walkthrough + detection.md + screenshots)
├── Detection-Rules/           # Consolidated Splunk queries for all attacks
├── Incident-Reports/          # Defender-perspective writeups per attack
├── MITREMapping/              # ATT&CK technique mapping
└── README.md
```

## Tools Used
- Splunk (SIEM) 
- Splunk Universal Forwarder 
- Sysmon 
- Kerbrute 
- CrackMapExec 
- Impacket 
- Evil-WinRM
- Hashcat
- Windows Event Viewer

## Key Findings & Lessons Learned

A few things this lab surfaced that go beyond the attacks themselves:

- **SMB signing blocks some tooling.** Hydra failed against Server 2022 because SMB signing was enabled (`signing:True`); CrackMapExec was used instead. A small example of how a default hardening control affects an attacker's options.
- **PowerShell logging requires explicit setup.** Script Block Logging (Event 4104) is off by default and had to be enabled via GPO. The PowerShell Operational channel also isn't forwarded by Splunk by default. It required adding the input and creating a dedicated index before events appeared.
- **DCSync can evade detection without proper auditing.** Detecting DCSync via Event 4662 depends on directory service auditing being configured. The attack succeeded and was visible as a burst of replication requests from a standard user account (`john.smith`) a strong behavioral indicator, since legitimate replication only originates from domain controllers.
- **Field extraction matters.** Without the Splunk Windows TA, some channels (PowerShell, DCSync) didn't parse cleanly into fields, requiring raw-event searching instead. A reminder that getting data *in* is only half the job.

