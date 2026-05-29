# Cybersecurity Portfolio

## Author

Michael Chaudhary — BSc Cybersecurity and Digital Forensics student focused on SOC analysis, SIEM monitoring, log analysis, and network security.

Hands-on cybersecurity portfolio built within isolated VMware-based Windows and Kali Linux lab environments.

This repository contains projects focused on:

- SIEM and log analysis
- Windows event monitoring
- Active Directory attack and detection
- Networking traffic inspection
- SMB enumeration
- Basic SOC workflow
- Security investigation and detection

---

# Lab Environment

## Infrastructure:

- VMware Workstation
- Windows Server 2022 (Domain Controller)
- Windows 11 Virtual Machine
- Kali Linux Virtual Machine

## Network Configuration

- Isolated internal VM network
- Host-only communication setup
- Controlled attack and monitoring environment

---

# Tools Used

## Security & Monitoring:

- Splunk Enterprise (indexer and search head)
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer
- Group Policy auditing

## Offensive Tooling (lab use):

- Kerbrute
- CrackMapExec
- Impacket (secretsdump, GetUserSPNs)
- Evil-WinRM
- Hashcat

## Networking & Analysis:

- Wireshark
- Nmap
- smbclient

## Operating Systems:

- Kali Linux
- Windows 11
- Windows Server 2022

---

# Projects:

## 1. AD Security Monitoring Lab

End to end Active Directory attack and detection project. Six common AD attacks were simulated against a Windows Server 2022 domain controller, with all events forwarded to a Splunk SIEM for detection. Each attack is paired with a detection writeup, Splunk queries, screenshots from Event Viewer and Splunk, and a SOC style incident report.

### Skills Demonstrated:

- Active Directory attack and defense
- Splunk SIEM configuration and querying
- Windows event log analysis (Security and PowerShell Operational channels)
- Sysmon process telemetry
- MITRE ATT&CK mapping
- Incident response documentation

### Attack Scenarios Covered:

- Brute Force (Password Spraying and Guessing)
- Domain Account Creation
- Privileged Group Modification
- Kerberoasting
- PowerShell Execution (encoded commands and download cradles)
- DCSync and Pass the Hash

Repository Folder: `AD-Security-Monitoring-Lab`

---

## 2. SMB Enumeration Lab:

Performed SMB service discovery and share enumeration within an isolated Windows/Kali lab environment.

### Skills Demonstrated:

- Network scanning
- SMB enumeration
- Service discovery
- Firewall behaviour analysis

Repository Folder: `SMB-Enumeration Lab`

---

## 3. Windows Log Analysis:

Investigated Windows security events and authentication logs generated during simulated attacks.

### Skills Demonstrated:

- Event Viewer analysis
- Failed login investigation
- Security event interpretation
- Basic incident triage

Repository Folder: `Window-Log-Analysis`

---

## 4. SIEM Detection Lab

Configured centralized logging and analyzed security alerts generated from simulated attacker activity.

### Skills Demonstrated

- SIEM configuration
- Log ingestion
- Alert investigation
- Detection workflow analysis

Repository Folder: `SIEM-Detection-Lab`

---

## 5. Network Traffic Analysis

Captured and analyzed network traffic using Wireshark to study communication patterns and suspicious activity.

### Skills Demonstrated

- Packet analysis
- Protocol inspection
- ICMP and DNS analysis
- Network visibility

Repository Folder: `Network-Traffic-Analysis`

---

# Key Learning Outcomes

- End to end attack and detection coverage for common Active Directory threats
- Hands on Splunk SIEM configuration, including custom input channels and indexes
- Understanding of Windows security logging across Security, PowerShell Operational, and Sysmon channels
- MITRE ATT&CK technique mapping applied to real lab events
- SOC style incident report writing
- Practical network analysis experience
- Service exposure and enumeration

---

# Future Improvements

Planned additions:

- Advanced SIEM correlation rules
- Threat intelligence integration
- Malware traffic analysis
- Detection engineering workflows
- Cloud security monitoring (Azure or AWS)

---

# Disclaimer

All activities were performed in isolated virtual lab environments for educational and defensive security purposes only.
