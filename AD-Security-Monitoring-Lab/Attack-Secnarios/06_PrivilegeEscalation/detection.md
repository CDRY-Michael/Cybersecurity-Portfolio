# Privilege Escalation (DCSync) — Detection

## Overview

Detects abuse of the AD replication protocol to extract password hashes from a domain controller. DCSync requests are valid Kerberos and DRSUAPI traffic; no exploit, no malware. The attack is identified by who is making the replication request (a user account, not a DC) and what permission is being exercised (`DS-Replication-Get-Changes-All`).

## MITRE ATT&CK (TTPs)

| Tactic            | Technique                                            | ID        |
| ----------------- | ---------------------------------------------------- | --------- |
| Credential Access | OS Credential Dumping: DCSync                        | T1003.006 |
| Defense Evasion   | Use Alternate Authentication Material: Pass the Hash | T1550.002 |

## Event IDs

| Event ID | Description                             | Notes                                       |
| -------- | --------------------------------------- | ------------------------------------------- |
| 4662     | Operation on a directory service object | The primary DCSync detection                |
| 4624     | Successful logon (logon type 3)         | Tracks Pass the Hash reuse of dumped hashes |

## Detection Queries

### DCSync by suspect subject

```spl
index=* EventCode=4662 Account_Name="john.smith"
| table _time, Account_Name, Object_Name, Properties
| sort -_time
```

### High fidelity hunt by replication GUID (production form)

```spl
index=* EventCode=4662 Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
  Account_Name!="*$"
| table _time, Account_Name, Object_Name, Properties
| sort -_time
```

Raw text fallback (when the Properties field is not extracted):

```spl
index=* EventCode=4662 "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" NOT "$"
| table _time, Account_Name, Object_Name
| sort -_time
```

### Pass the Hash follow up

```spl
index=* EventCode=4624 Logon_Type=3 Authentication_Package_Name=NTLM
| table _time, Account_Name, Workstation_Name, Source_IP
| sort -_time
```

## Key Indicators (IOCs)

- 4662 with Subject = a user account (not a DC computer account) and Object Name = the domain root.
- Properties field containing the GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`). The related GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`) and `89e95b76-444d-4c62-991a-0facbeda640c` (`DS-Replication-Get-Changes-In-Filtered-Set`) are also DCSync indicators.
- A burst of 4662 events from one user account within seconds (this lab saw 39 in a few seconds during the full dump).
- Subsequent NTLM logons (4624 logon type 3) from an unexpected source IP, using accounts whose hashes were exposed. This is the Pass the Hash signal.

## Notes

- 4662 detection only works if Directory Service Access auditing is enabled and a SACL is set on the domain object for the `Replicating Directory Changes` permissions. This is not on by default in many environments, which is why DCSync often evades detection in the wild.
- The lab had auditing enabled, which is why the 4662 events were captured.
- Legitimate replication generates 4662 from DC computer accounts (e.g. `DC01$`). Always filter those out with `Account_Name!="*$"` or by an allowlist of DC accounts.
- The `Properties` field in 4662 is a string of access mask values and GUIDs. If field extraction is not configured, fall back to a raw text search for the GUID.
- The Pass the Hash step using dumped NT hashes produces 4624 logon type 3 with `Authentication Package = NTLM`. Correlating PTH activity to accounts whose hashes were known to be exposed is a useful follow on detection.
- Remediation for confirmed DCSync of krbtgt: rotate the krbtgt password twice, at least 10 hours apart, to invalidate forged Golden Tickets.
