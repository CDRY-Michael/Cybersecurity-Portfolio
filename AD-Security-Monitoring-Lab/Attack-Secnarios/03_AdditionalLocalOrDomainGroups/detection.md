# Additional Local/Domain Groups — Detection

## Overview

Detects users being added to privileged groups (Domain Admins, local Administrators, Enterprise Admins). A common privilege-escalation and persistence move once an attacker has admin-equivalent access: promote an existing account rather than create a new one.

## MITRE ATT&CK (TTPs)

| Tactic               | Technique            | ID    |
| -------------------- | -------------------- | ----- |
| Privilege Escalation | Account Manipulation | T1098 |
| Persistence          | Account Manipulation | T1098 |

## Event IDs

| Event ID | Description                                              | Group Type |
| -------- | -------------------------------------------------------- | ---------- |
| 4728     | A member was added to a security-enabled global group    | Global     |
| 4732     | A member was added to a security-enabled local group     | Local      |
| 4756     | A member was added to a security-enabled universal group | Universal  |

## Detection Queries

### All group additions

```spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, EventCode, Account_Name, Group_Name
| sort -_time
```

### High-value groups only

```spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
  Group_Name IN ("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
| table _time, EventCode, Account_Name, Group_Name, Member_Name
| sort -_time
```

## Key Indicators (IOCs)

- Any addition to Domain Admins, Enterprise Admins, Schema Admins, or local Administrators on a DC.
- Addition performed by a subject that doesn't normally manage groups (a service account, an end-user account).
- Multiple group additions from the same subject in a short window — pattern of an attacker stacking privileges.
- 4728/4732 events in close sequence for the same member suggest both global and local escalation, as seen in this lab.

## Notes

- 4728 = global, 4732 = local, 4756 = universal. A detection that only watches 4728 misses local-group escalation.
- Member field in 4728 is a distinguished name (`CN=john smith,CN=Users,DC=corp,DC=local`). In 4732 it's the SAM account name (`CORP\john.smith`). Account name field extraction can differ between the two — fall back to raw text search if needed.
- Both events require Security Group Management auditing, which is enabled by default on modern AD.
