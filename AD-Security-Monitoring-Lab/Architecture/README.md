# Lab Architecture

![Lab Topology](ad_security_lab_topology.png)

## Overview
An isolated virtual lab built in VMware Workstation on a single host, using a
custom (host-only style) VMnet so no lab traffic reaches the physical network.
The lab simulates Active Directory attacks and centralises Windows logs in
Splunk for detection.

## Hosts

| Role | Hostname | OS | IP | Key Software |
|------|----------|-----|-----|--------------|
| Domain Controller | DC01 | Windows Server 2022 | 192.168.40.10 | AD DS, DNS, Splunk Universal Forwarder, Sysmon |
| Workstation / SIEM | DESKTOP-82HJBKD | Windows 11 | 192.168.40.129 | Domain-joined, Splunk Enterprise (indexer + search head), Sysmon |
| Attacker | kali | Kali Linux | 192.168.40.130 | Kerbrute, CrackMapExec, Impacket, Evil-WinRM, Hashcat |

Domain: `corp.local`
Network: VMware custom VMnet, 192.168.40.0/24 (isolated)