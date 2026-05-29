# IR-001: Brute Force Authentication Activity

| Field       | Value                       |
| ----------- | --------------------------- |
| Incident ID | IR-001                      |
| Severity    | Medium                      |
| Status      | Closed                      |
| Detected    | 2026-05-27 05:24 UTC        |
| Reported by | Splunk detection            |
| Analyst     | Michael Chaudhary           |
| MITRE       | T1110.001, T1110.003, T1201 |

## Summary

A burst of Kerberos pre authentication failures (Event 4771) was observed from a single source IP against multiple domain accounts, followed by repeated NTLM logon failures (Event 4625) against one account that eventually locked out (Event 4740). The pattern appears consistent with password spraying followed by targeted password guessing from the same attacker host.

## Detection

- Splunk search on `EventCode=4771` returned 9 failures across 4 accounts within seconds.
- Splunk search on `EventCode=4625 OR EventCode=4740` returned a cluster of 64 failures against `john.smith` from the same source IP, ending in an account lockout (4740).
- A CrackMapExec query for the domain password policy (`--pass-pol`) was also recorded in the timeline shortly before the spray, suggesting prior reconnaissance.

## Timeline (UTC)

| Time                 | Activity                                                   |
| -------------------- | ---------------------------------------------------------- |
| 05:24:47             | First 4771 against Administrator from 192.168.40.130.      |
| 05:24:47 to 05:24:51 | 4771 cluster across alice.brown, finance.user, john.smith. |
| 06:25:32 to 06:25:39 | 4625 cluster against john.smith from 192.168.40.130.       |
| 06:40:39             | 4740 account lockout fired for john.smith.                 |

## Impact

- One valid domain credential was confirmed by attacker tooling: `corp.local\john.smith`.
- No successful interactive logon to a workstation was observed within this incident window. Further investigation would be needed to confirm.
- Account `john.smith` was temporarily locked, which blocks further attempts against that account specifically.

## Indicators of Compromise (IOCs)

- Source IP: `192.168.40.130`
- Targeted accounts: Administrator, alice.brown, finance.user, john.smith
- Confirmed valid credential: `corp.local\john.smith`
- Attack signatures observed: 4771 burst against the KDC (consistent with Kerbrute spraying), 4625 cluster over SMB (consistent with CrackMapExec or similar guessing tool)

## Recommendations

1. Reset the password for `john.smith`. The current password was guessed within a small wordlist, so any replacement should be selected to avoid common patterns.
2. Block `192.168.40.130` at the perimeter while the investigation is open.
3. Hunt for any 4624 (successful logon) sourced from `192.168.40.130` across all hosts during the incident window. This would confirm whether any sprayed credentials were actually used.
4. Add a Splunk detection that flags 4771 failures against multiple accounts from the same source within a short window. The lockout policy caught the guessing phase, but did not detect the spray, which is a coverage gap worth closing.
5. Review other accounts for password reuse. If similar weak passwords exist on more privileged accounts, the same attack would succeed against them.

## Status

- Closed.
- Detection coverage takeaway: spraying generates 4771 (Kerberos) while guessing generates 4625 / 4740 (NTLM). A detection that watches only one path would miss the other.
- Open item for follow up: the spray itself was not detected until guessing triggered the lockout. A detection focused on 4771 burst rate would have caught the earlier activity.
