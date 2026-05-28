# AD Security Monitoring Lab

A home lab built to simulate common Active Directory attacks and detect them using a Splunk SIEM. The goal was to understand the full picture of each attack — how it works from the attacker's side, what artifacts it leaves in Windows event logs, and how to detect it — and to map each technique to MITRE ATT&CK.

This project was built as a self-directed learning exercise while studying for my BSc in Cybersecurity.

## Objectives
- Stand up a realistic AD environment (domain controller, workstation, attacker host, SIEM).
- Execute six common AD attacks against the domain.
- Forward Windows security and operational logs to Splunk and write detection queries for each attack.
- Document the detection logic and map each technique to MITRE ATT&CK.

## Environment

| Role | OS | Details |
|------|-----|---------|
| Domain Controller | Windows Server 2022 | `corp.local`, DC IP `192.168.40.10`, Splunk Universal Forwarder, Sysmon |
| Workstation / SIEM | Windows 11 | Domain-joined (`192.168.40.129`), Splunk Enterprise (indexer + search head), Sysmon |
| Attacker | Kali Linux | `192.168.40.130` — Kerbrute, CrackMapExec, Impacket, Evil-WinRM, Hashcat |

Network: VMware custom VMnet, `192.168.40.0/24` (isolated). Logs from the DC and workstation are forwarded to Splunk on the Windows 11 host, where detection queries are run against the Security, PowerShell/Operational, and Sysmon/Operational channels.

See [Architecture/](Architecture/) for the full topology diagram and configuration notes.
