# MITRE ATT&CK Mapping

This lab demonstrates seven ATT&CK tactics across thirteen techniques and sub techniques. Each row links to the scenario folder where the technique was exercised and the incident report where the detection was documented.

## By Tactic

### Reconnaissance / Discovery

| ID    | Technique                 | Scenario      | Incident Report |
| ----- | ------------------------- | ------------- | --------------- |
| T1201 | Password Policy Discovery | 01_BruteForce | IR-001          |

### Credential Access

| ID        | Technique                                      | Scenario               | Incident Report |
| --------- | ---------------------------------------------- | ---------------------- | --------------- |
| T1110.001 | Brute Force: Password Guessing                 | 01_BruteForce          | IR-001          |
| T1110.003 | Brute Force: Password Spraying                 | 01_BruteForce          | IR-001          |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | 04_Kerberoasting       | IR-004          |
| T1003.006 | OS Credential Dumping: DCSync                  | 06_PrivilegeEscalation | IR-006          |

### Initial Access / Lateral Movement

| ID        | Technique                                            | Scenario   | Incident Report        |
| --------- | ---------------------------------------------------- | ---------- | ---------------------- |
| T1078     | Valid Accounts                                       | 02, 03, 06 | IR-002, IR-003, IR-006 |
| T1021.006 | Remote Services: Windows Remote Management           | 02, 03     | IR-002, IR-003         |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | 06         | IR-006                 |

### Persistence

| ID        | Technique                      | Scenario                 | Incident Report |
| --------- | ------------------------------ | ------------------------ | --------------- |
| T1136.002 | Create Account: Domain Account | 02_DomainAccountCreation | IR-002          |
| T1098     | Account Manipulation           | 02, 03                   | IR-002, IR-003  |

### Privilege Escalation

| ID    | Technique                               | Scenario                         | Incident Report |
| ----- | --------------------------------------- | -------------------------------- | --------------- |
| T1098 | Account Manipulation (Privileged Group) | 03_AdditionalLocalOrDomainGroups | IR-003          |

### Execution

| ID        | Technique                                     | Scenario               | Incident Report |
| --------- | --------------------------------------------- | ---------------------- | --------------- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | 05_PowerShellExecution | IR-005          |

### Defense Evasion

| ID        | Technique                                            | Scenario               | Incident Report |
| --------- | ---------------------------------------------------- | ---------------------- | --------------- |
| T1027     | Obfuscated Files or Information                      | 05_PowerShellExecution | IR-005          |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | 05_PowerShellExecution | IR-005          |

## Coverage Summary

| Tactic               | Techniques Covered                                         |
| -------------------- | ---------------------------------------------------------- |
| Reconnaissance       | 1                                                          |
| Credential Access    | 4                                                          |
| Initial Access       | 1                                                          |
| Persistence          | 2                                                          |
| Privilege Escalation | 1                                                          |
| Lateral Movement     | 2                                                          |
| Defense Evasion      | 2                                                          |
| Execution            | 1                                                          |
| **Total techniques** | **13** (some overlap across tactics, e.g. T1078 and T1098) |

## Notes

T1078 (Valid Accounts) and T1098 (Account Manipulation) appear under multiple tactics because ATT&CK lists them that way. T1078 is both an Initial Access and a Persistence technique depending on context, and T1098 covers both Persistence and Privilege Escalation. The rows above reflect how each one was used in this lab.

Sysmon Event 1 is not an ATT&CK technique itself but supports detection of T1059.001 by capturing process lineage. It is referenced in the PowerShell scenario and IR-005.
