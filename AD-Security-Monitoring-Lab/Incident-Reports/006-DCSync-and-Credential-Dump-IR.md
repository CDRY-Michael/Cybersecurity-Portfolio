# IR-006: DCSync Credential Dump and Pass the Hash

| Field       | Value                |
| ----------- | -------------------- |
| Incident ID | IR-006               |
| Severity    | Critical             |
| Status      | Closed               |
| Detected    | 2026-05-28 19:04 UTC |
| Reported by | Splunk detection     |
| Analyst     | Michael Chaudhary    |
| MITRE       | T1003.006, T1550.002 |

## Summary

The user account `john.smith` issued a burst of directory service replication requests against the domain controller, consistent with a DCSync attack. Replication of password material from a non domain controller account is a defining indicator of full domain credential compromise. Hashes for `Administrator`, `krbtgt`, and every domain account were extracted. The captured `Administrator` NT hash was then reused to authenticate to the DC via Pass the Hash, confirming the dump was operationally successful.

This incident represents full domain compromise.

## Detection

- Splunk search on `EventCode=4662 Account_Name="john.smith"` returned 39 events, all with `Properties` containing the replication GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`).
- All 39 events occurred within a few seconds, against the domain root object (`DC=corp,DC=local`), with `Accesses: Control Access`.
- The subject was `CORP\john.smith`, a user account. Legitimate replication originates from domain controller computer accounts (`DC01$`). A user account performing replication is the high fidelity DCSync signature.
- A subsequent Event 4624 (Logon Type 3, NTLM) recorded a successful Pass the Hash logon as `Administrator` from the same source IP.

## Timeline (UTC)

| Time         | Activity                                                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| 19:04:06     | 39 x Event 4662, replication GUID `1131f6ad...`, subject `john.smith`, target `DC=corp,DC=local`. Burst lasted under 1 second. |
| 19:04 approx | Attacker tooling completed targeted dumps of `Administrator` and `krbtgt`, followed by a full domain dump.                     |
| 19:05 approx | Pass the Hash authentication as `Administrator` from 192.168.40.130, confirming the captured NT hash was used.                 |

## Impact

- The NT hash and Kerberos keys for `Administrator` (`579da618cfbfa85247acf1f800a280a4`) and for the `krbtgt` account (`be35f0452c852f3f4b0de0d5aef14d1d`) are exposed.
- NT hashes and Kerberos keys for every domain account are exposed, including service accounts and the previously created `Hacker` account.
- The `krbtgt` hash being exposed means the attacker can forge Golden Tickets, granting arbitrary domain access for an unlimited lifetime. This is functionally total domain compromise.
- Pass the Hash was already used to authenticate as `Administrator`, confirming the dump is not just theoretical exposure. The credentials are in active use.
- Any account in the dump can be used for Pass the Hash against any host accepting NTLM, until the affected accounts have their passwords rotated.

## Indicators of Compromise (IOCs)

- Account performing replication: `corp.local\john.smith`
- Source IP: `192.168.40.130`
- Replication GUID observed in 4662 Properties: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- Object accessed: `DC=corp,DC=local`
- Accounts with confirmed exposed credentials: `Administrator`, `krbtgt`, `john.smith`, `alice.brown`, `it.admin`, `finance.user`, `svc_sql`, `Hacker`, machine accounts `DC01$` and `DESKTOP-82HJBKD$`
- Tools observed in the timeline: `impacket-secretsdump`, `evil-winrm -H` (Pass the Hash)
- Related incidents: IR-001 through IR-005

## Recommendations

This incident triggers a full domain compromise response. The actions below are listed roughly in priority order.

1. Rotate the `krbtgt` account password twice, with at least 10 hours between resets. This is the only way to invalidate any Golden Tickets the attacker may have already forged. The 10 hour gap is required because `krbtgt` keeps two password versions active to avoid breaking in flight tickets.
2. Force a password reset on every domain account. Every NT hash in the dump is reusable for Pass the Hash until the corresponding password is changed.
3. Reset all service account passwords. Service accounts often have long passwords specifically because they are rarely rotated, which makes them prime Pass the Hash targets.
4. Disable `john.smith` and remove from all privileged groups. This account was the pivot for the entire attack chain. Preserve the account for forensic review rather than deleting it.
5. Block `192.168.40.130` at the perimeter.
6. Review domain controller security. The fact that `john.smith` held `Domain Admins` at the time of the DCSync (from IR-003) is the upstream cause. Review who should hold Domain Admins, restrict to a small set of named tier-0 admin accounts, and consider implementing a tiered administration model.
7. Verify that Directory Service Access auditing is enabled with a SACL on the domain object for the replication permissions. In this lab the SACL was configured, which is why 4662 events were captured. In many production environments this is not the default, and DCSync passes silently.
8. Add a Splunk detection that alerts on any 4662 event containing the replication GUIDs from a non machine account (`Account_Name!="*$"`). This is a very low volume, very high fidelity signal.
9. Hunt for any subsequent activity from the exposed accounts across the environment. The dump itself is hours ago, so the attacker has had time to use the credentials.

## Status

- Closed.
- Detection coverage takeaway: DCSync produces a burst of 4662 events with a specific replication GUID in the Properties field. The subject (a user, not a DC) and the burst pattern (dozens of events in under a second) are both strong indicators on their own, and unmistakable when combined.
- Open item for follow up: this incident represents the end state of the attack chain that began in IR-001. The full chain (credential compromise → group elevation → code execution on DC → DCSync → Pass the Hash) is now documented and traceable across the six incident reports. The root cause for the chain remains the weak password on `john.smith` that allowed the initial brute force to succeed.
