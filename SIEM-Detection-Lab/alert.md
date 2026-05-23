# SIEM Home Lab Alerts

## Overview

The following alerts and detections were configured and tested within Splunk Enterprise using Windows Security logs and Sysmon telemetry.

The alerts were designed to identify suspicious authentication activity, process execution events, PowerShell usage, and attacker-related network activity.

---

# Alert 1: Failed Login Detection

## Alert Name

Failed Login Attempt Detection

---

## Purpose

Detect failed authentication attempts against the Windows target system.

---

## Splunk Query

```spl
index=* EventCode=4625
```

---

## Triggered Activity

- invalid login attempts
- incorrect password attempts
- unauthorized authentication attempts

---

## Monitored Data

- username
- source workstation
- source IP address
- authentication package
- logon type

---

## Security Relevance

Repeated failed login attempts may indicate:

- brute force attacks
- password spraying
- unauthorized access attempts
- credential guessing activity

---

# Alert 2: Successful Login Detection

## Alert Name

Successful Login Detection

---

## Purpose

Monitor successful user authentication events within the environment.

---

## Splunk Query

```spl
index=* EventCode=4624
```

---

## Triggered Activity

- successful user logins
- network authentication activity
- authenticated session creation

---

## Monitored Data

- authenticated username
- logon type
- workstation name
- authentication process
- source network information

---

## Security Relevance

Successful login monitoring helps identify:

- unauthorized account access
- unusual login behavior
- attacker persistence
- suspicious account activity

---

# Alert 3: Sysmon Process Creation Detection

## Alert Name

Process Creation Monitoring

---

## Purpose

Detect newly created processes using Sysmon Event ID 1.

---

## Splunk Query

```spl
index=* EventCode=1
```

---

## Triggered Activity

- process execution
- command execution
- application launches
- script execution

---

## Monitored Data

- process name
- command line arguments
- process hashes
- parent process
- execution path

---

## Security Relevance

Process creation monitoring helps detect:

- suspicious process execution
- malware activity
- script-based attacks
- attacker tools
- unauthorized software execution

---

# Alert 4: PowerShell Activity Detection

## Alert Name

PowerShell Execution Detection

---

## Purpose

Monitor PowerShell execution activity through Sysmon telemetry.

---

## Splunk Query

```spl
index=* EventCode=1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" powershell.exe
```

---

## Triggered Activity

- PowerShell execution
- script execution
- command-line PowerShell usage

---

## Monitored Data

- PowerShell process execution
- parent process relationships
- command line activity
- execution paths

---

## Security Relevance

PowerShell monitoring helps identify:

- malicious scripting activity
- attacker automation
- living-off-the-land techniques
- suspicious administrative behavior

---

# Alert 5: Attacker IP Detection

## Alert Name

Attacker Source IP Detection

---

## Purpose

Detect activity associated with the Kali Linux attacker machine.

---

## Splunk Query

```spl
index=* "192.168.40.130"
```

---

## Triggered Activity

- attacker-related events
- authentication attempts
- network communication
- reconnaissance activity

---

## Monitored Data

- source IP address
- destination IP address
- associated processes
- authentication activity
- network events

---

## Security Relevance

Source IP monitoring helps identify:

- attacker systems
- suspicious network activity
- reconnaissance attempts
- unauthorized communication

---

# Alert Testing

The alerts were tested using simulated attacker activity from the Kali Linux system.

Tested activities included:

- failed login attempts
- PowerShell execution
- process execution
- network communication
- reconnaissance scanning

---

# Alert Outcomes

The configured detections generated observable events within Splunk and demonstrated:

- centralized security monitoring
- event correlation
- endpoint visibility
- authentication monitoring
- process monitoring
- attacker activity tracking

---

# Detection Capabilities Demonstrated

- Authentication monitoring
- Endpoint telemetry analysis
- Process creation monitoring
- PowerShell detection
- Network activity monitoring
- Source IP correlation
- Threat visibility
- Security event investigation
