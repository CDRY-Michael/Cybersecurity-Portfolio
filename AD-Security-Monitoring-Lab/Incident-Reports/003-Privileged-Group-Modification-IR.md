# IR-003: Privileged Group Modification

| Field       | Value                   |
| ----------- | ----------------------- |
| Incident ID | IR-003                  |
| Severity    | High                    |
| Status      | Closed                  |
| Detected    | 2026-05-28 03:18 UTC    |
| Reported by | Splunk detection        |
| Analyst     | Michael Chaudhary       |
| MITRE       | T1098, T1078, T1021.006 |

## Summary

The domain user `john.smith` was added to both the `Domain Admins` global group and the local `Administrators` group on `DC01` within a short window. Both changes were made by the built in `Administrator` account from an Evil-WinRM session. This is consistent with an attacker escalating an existing low privilege user account to high privilege, which is a common persistence and privilege escalation pattern after initial credential compromise.

## Detection

- Splunk search on `EventCode=4728 OR EventCode=4732 OR EventCode=4756` returned three group additions within a short window.
- Event 4728 (global group): `john.smith` added to `CORP\Domain Admins`.
- Event 4732 (local group): `john.smith` added to `BUILTIN\Administrators` on `DC01`.
- Same source subject (`CORP\Administrator`) and same `LogonId` across both events, indicating the same session.
- `john.smith` was the same account confirmed as compromised in IR-001. The chain from credential exposure to privilege escalation is therefore traceable end to end.

## Timeline (UTC)

| Time     | Activity                                                            |
| -------- | ------------------------------------------------------------------- |
| 03:18:57 | Event 4728: `john.smith` added to `Domain Admins`.                  |
| 03:20:09 | Event 4732: `john.smith` added to local `Administrators` on `DC01`. |

## Impact

- `john.smith` now holds `Domain Admins`, `Enterprise Admins`, and local `Administrators` rights inherited through these groups. This grants full administrative control of the domain.
- The originating session was `CORP\Administrator`, indicating the built in administrator credential was used to perform the change. That credential is presumed compromised.
- This event materially expands the attack surface. Any subsequent action by `john.smith` would carry full domain privilege.
- No further activity from `john.smith` was visible within this incident window. Follow on hunting is recommended.

## Indicators of Compromise (IOCs)

- Account elevated: `corp.local\john.smith`
- Groups affected: `Domain Admins` (global), `Administrators` (local on DC01)
- Subject performing the change: `CORP\Administrator` via Evil-WinRM session
- Source IP for the WinRM session: `192.168.40.130`
- Related incident: IR-001 (initial credential compromise of `john.smith`)

## Recommendations

1. Remove `john.smith` from `Domain Admins` and local `Administrators`. Preserve the account itself pending review, since deleting it during an active investigation can disrupt evidence collection.
2. Disable `john.smith` pending password reset. The account is now confirmed compromised and elevated.
3. Force a password reset on `Administrator`. The session that performed the elevation used the built in admin credential, which should be considered exposed.
4. Hunt for any activity performed by `john.smith` while elevated. Look for 4624 (logon), 4672 (special privileges assigned), 4769 (TGS requests against sensitive services), and 4662 (directory service access).
5. Add a detection rule that alerts on any modification to high value groups (`Domain Admins`, `Enterprise Admins`, `Schema Admins`, local `Administrators`). These are low frequency, high impact changes and warrant immediate review.
6. Link this incident to IR-001 and IR-002 in the case record. A connected timeline tells a clearer story than treating each incident in isolation.

## Status

- Closed.
- Detection coverage takeaway: 4728 (global) and 4732 (local) are different event IDs for the same conceptual action. A detection that watches only one misses the other path. Both should be monitored, with 4756 (universal) included for completeness.
- Open item for follow up: the `Administrator` credential has now been involved in multiple incidents. A broader review of how that credential is stored, used, and rotated is warranted.
