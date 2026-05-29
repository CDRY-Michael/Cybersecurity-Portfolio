# IR-002: Unauthorized Domain Account Creation

| Field       | Value                              |
| ----------- | ---------------------------------- |
| Incident ID | IR-002                             |
| Severity    | High                               |
| Status      | Closed                             |
| Detected    | 2026-05-27 02:40 UTC               |
| Reported by | Splunk detection                   |
| Analyst     | Michael Chaudhary                  |
| MITRE       | T1078, T1021.006, T1136.002, T1098 |

## Summary

A new domain account named `Hacker` was created on the domain controller and added to the `HelpDesk` security group within a short window. Both actions were performed by the built in `Administrator` account from an Evil-WinRM session originating outside the normal administrative workstation. The combination of account creation followed immediately by group addition is consistent with an attacker establishing persistence after obtaining administrator credentials.

## Detection

- Splunk search on `EventCode=4720 OR EventCode=4728` for the account name `hacker` returned two correlated events.
- Event 4720 (User Account Management): `Hacker` account created on `DC01.corp.local`.
- Event 4728 (Security Group Management): `Hacker` added to `CORP\HelpDesk` approximately two minutes after creation.
- Both events show the same subject (`CORP\Administrator`) and the same `LogonId`, which suggests they came from the same interactive session.

## Timeline (UTC)

| Time         | Activity                                                                                           |
| ------------ | -------------------------------------------------------------------------------------------------- |
| 02:38 approx | Inbound WinRM authentication observed as `Administrator` from 192.168.40.130 (Evil-WinRM session). |
| 02:40:58     | Event 4720: `Hacker` account created with `Password@123`.                                          |
| 02:42:48     | Event 4728: `Hacker` added to `HelpDesk` group.                                                    |

## Impact

- A new domain account exists that was not part of any approved change request.
- The `Hacker` account holds membership in `HelpDesk`, which is a privileged group in this environment. The account is therefore a viable foothold for further activity.
- The originating session used valid `Administrator` credentials, which suggests credential compromise had already occurred before this incident was detected. Further investigation would be needed to determine the source of the credential exposure.
- No further activity from the `Hacker` account was observed within this incident window.

## Indicators of Compromise (IOCs)

- New account: `CORP\Hacker` (`CN=Hacker,CN=Users,DC=corp,DC=local`)
- Group affected: `CORP\HelpDesk`
- Subject performing the action: `CORP\Administrator` (from the WinRM session)
- Source IP for the WinRM session: `192.168.40.130`
- Tools observed in the timeline: CrackMapExec (credential validation), Evil-WinRM (interactive session), `net user` and `net group` commands

## Recommendations

1. Disable the `Hacker` account and remove it from `HelpDesk`. Preserve the account itself rather than deleting it, to retain artifacts for forensic review.
2. Force a password reset on `Administrator`. The account credential is presumed exposed based on the WinRM session origin.
3. Restrict WinRM and remote management access. `Remote Management Users` membership should be limited to specific administrative accounts, and WinRM access from non administrative subnets should be blocked at the firewall.
4. Hunt for activity by the `Hacker` account across the environment in the time window after creation. Look for 4624 (successful logon), 4672 (special privileges assigned), and any 4768 / 4769 Kerberos events.
5. Add a detection rule that correlates a 4720 followed by a 4728 for the same account within a short window. Creation alone can be legitimate IT work, but creation immediately followed by privileged group membership is a stronger signal worth alerting on.

## Status

- Closed.
- Detection coverage takeaway: 4720 by itself is high volume in normal IT operations and easy to dismiss. Correlating it with 4728 in a short window produces a much higher fidelity signal.
- Open item for follow up: investigate how the `Administrator` credential was obtained in the first place, since that is the upstream root cause for this incident.
