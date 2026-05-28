# Brute Force — Detection

## Overview

Covers two credential-access techniques against the domain:

- Password Guessing: repeated authentication attempts against a single account, eventually triggering lockout.
- Password Spraying: a small set of common passwords tried across many accounts to avoid lockout.

## MITRE ATT&CK (TTPs)

| Tactic            | Technique                      | ID        |
| ----------------- | ------------------------------ | --------- |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Discovery         | Password Policy Discovery      | T1201     |

## Event IDs

| Event ID | Description                        | Technique         |
| -------- | ---------------------------------- | ----------------- |
| 4625     | Failed logon                       | Password Guessing |
| 4740     | Account locked out                 | Password Guessing |
| 4771     | Kerberos pre-authentication failed | Password Spraying |

## Detection Queries

### Password Guessing — failed logons + lockout

```spl
index=* (EventCode=4625 OR EventCode=4740)
| table _time, EventCode, Account_Name
| sort -_time
```

### Password Spraying — Kerberos pre-auth failures

```spl
index=* EventCode=4771
| table _time, Account_Name
| sort -_time
```

## Key Indicators (IOCs)

- Guessing: many 4625 events against a single account in a short window, followed by a 4740 lockout for that account. Source IP in the lab was 192.168.40.130 (Kali).
- Spraying: 4771 failures across multiple different accounts at near-identical timestamps, the same password tried account by account.
- A burst of failures from a single source host is a strong signal for either technique.

## Notes

- Kerbrute generates 4771 (Kerberos pre-auth failure), not 4625, because the spray authenticates against the KDC rather than over SMB/NTLM. A detection that only watches 4625 would miss a Kerberos-based spray.
- The 4625 detail showed LogonType 3 (network), NTLM, and SubStatus 0xc000006a (bad password).
- The account lockout policy was temporarily enabled in the lab to force the 4740 event during guessing. The pass-pol check beforehand showed the lockout threshold was unset at spray time.
- Tooling note: Hydra failed against Server 2022 because SMB signing was enabled (signing:True), so CrackMapExec was used instead. A default hardening control blocked a common brute-force tool.
