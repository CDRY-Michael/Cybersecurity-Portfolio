# SIEM Home Lab Findings

## Summary

Security monitoring and event analysis were successful using Splunk Enterprise and Sysmon within an isolated VMware home lab.

Logs from the Windows 11 target machine were collected, indexed, and analyzed to identify authentication events, process activity, PowerShell execution, and attacker-related network activity originating from a Kali Linux system.

---

# Key Findings

## Failed Login Events Detected

Windows Security Event ID 4625 captured failed authentication attempts against the target machine.

Observed details included:

- invalid username or password attempts
- source workstation name
- source IP address
- failed logon type
- authentication package information

The events demonstrated how failed authentication attempts can be identified and investigated through centralized logging.

---

## Successful Login Events Observed

Windows Security Event ID 4624 recorded successful user authentication activity.

Observed details included:

- authenticated user account
- logon type
- workstation name
- logon process information
- network authentication data

This demonstrated visibility into successful authentication behavior within the environment.

---

## Sysmon Process Creation Monitoring Successful

Sysmon Event ID 1 captured process creation activity on the Windows endpoint.

Observed activity included:

- PowerShell execution
- ipconfig execution
- parent-child process relationships
- command line arguments
- process metadata
- executable hashes

This demonstrated enhanced endpoint visibility beyond standard Windows event logging.

---

## PowerShell Activity Successfully Logged

PowerShell execution activity was identified through Sysmon process creation logs.

Observed details included:

- powershell.exe execution
- parent process relationships
- command execution visibility
- command line logging

This demonstrated how PowerShell usage can be monitored through endpoint telemetry.

---

## Attacker IP Activity Correlated

Splunk searches successfully identified events associated with the Kali Linux attacker machine using source IP correlation.

Observed activity included:

- authentication attempts
- network communication
- service interaction activity
- attacker-related event traces

The attacker system IP address `192.168.40.130` was successfully identified across multiple event sources.

---

## Network Connection Events Captured

Sysmon network connection logging successfully captured communication activity between systems within the lab environment.

Observed details included:

- source IP addresses
- destination IP addresses
- source ports
- destination ports
- associated processes
- TCP communication activity

This demonstrated endpoint-level network visibility through Sysmon telemetry.

---

## Centralized Log Collection Successful

Splunk successfully centralized and indexed Windows Security and Sysmon logs from the target machine.

Collected log sources included:

- Windows Security logs
- Sysmon Operational logs
- process creation events
- authentication events
- network connection events

This demonstrated centralized security event monitoring capabilities.

---

## Security Event Timeline Visualization Created

A Splunk dashboard was successfully configured to visualize security event activity over time.

Dashboard visualization included:

- failed login activity
- PowerShell events
- attacker IP activity
- overall event volume timeline

This improved visibility into security-related activity within the environment.

---

# Security Impact

The project demonstrated how SIEM technologies and endpoint telemetry can improve visibility into authentication activity, process execution, and network communication.

The findings highlighted how centralized logging enables:

- attacker activity tracking
- authentication monitoring
- endpoint visibility
- process investigation
- event correlation
- network activity analysis

The lab also demonstrated the importance of monitoring Windows event logs and Sysmon for threat detection and incident investigation.

---

# Skills Demonstrated

- SIEM monitoring
- Splunk log analysis
- Sysmon analysis
- Windows event analysis
- Authentication monitoring
- Process creation analysis
- PowerShell monitoring
- Network activity investigation
- Event correlation
- Threat detection
- Security monitoring
- Dashboard analysis
- Endpoint telemetry analysis
- Security documentation
