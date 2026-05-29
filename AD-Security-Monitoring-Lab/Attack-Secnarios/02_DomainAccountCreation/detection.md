# Domain Account Creation — Detection

## Overview

Detects creation of a new domain account and its addition to a privileged group. A common persistence technique after credential compromise: a planted account survives password resets on the originally compromised account.

## MITRE ATT&CK (TTPs)

| Tactic      | Technique                      | ID        |
| ----------- | ------------------------------ | --------- |
| Persistence | Create Account: Domain Account | T1136.002 |
| Persistence | Account Manipulation           | T1098     |

## Event IDs

| Event ID | Description                                           | Category                  |
| -------- | ----------------------------------------------------- | ------------------------- |
| 4720     | A user account was created                            | User Account Management   |
| 4728     | A member was added to a security-enabled global group | Security Group Management |

## Detection Queries

### Lab-specific (filtered by account name)

```spl
index=* "hacker" ("EventCode=4728" OR "EventCode=4720")
| table _time, EventCode, Account_Name
```

### Production-style (any 4720 + 4728)

```spl
index=* (EventCode=4720 OR EventCode=4728)
| table _time, EventCode, Account_Name, Member_Name, Group_Name
| sort _time
```

## Key Indicators (IOCs)

- A 4720 closely followed by a 4728 for the same target account, from the same subject session. Account creation alone can be legitimate; the immediate group addition is the suspicious pattern.
- Creation by an unexpected subject (a service account, or any account that doesn't normally manage users).
- New accounts added to high-value groups: Domain Admins, Enterprise Admins, HelpDesk, account operators.

## Notes

- 4720 fires under User Account Management. 4728 fires under Security Group Management. Both require their audit policies enabled, which is the default on modern AD.
- The Member field in 4728 is the distinguished name (`CN=Hacker,CN=Users,DC=corp,DC=local`), not the SAM account name. If a Splunk column comes back blank, fall back to a raw text search for the account name.
- The attack chain in this lab: CME confirmed admin creds, Evil-WinRM opened a remote session, `net user /add /domain`, `net group /add /domain`. The WinRM logon itself generates a 4624 (logon type 3) as supporting context.
